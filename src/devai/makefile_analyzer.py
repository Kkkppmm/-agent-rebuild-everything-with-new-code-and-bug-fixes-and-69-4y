"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = (
    "Makefile",
    "makefile",
    "GNUmakefile",
    "gnumakefile",
)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+.*(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|\$\{|~/?\s|/\*)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
CHMOD_SETUID_PATTERN = re.compile(r"\bchmod\s+[ug]?[+-]?[sx]", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b[^\n]*--force\b", re.IGNORECASE)
INSECURE_CURL_PATTERN = re.compile(r"\bcurl\b[^\n]*(-k|--insecure)\b", re.IGNORECASE)
INSECURE_WGET_PATTERN = re.compile(
    r"\bwget\b[^\n]*(--no-check-certificate)\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"\bdocker\s+(run|create)\b[^\n]*--privileged\b",
    re.IGNORECASE,
)
UNPINNED_DOCKER_IMAGE_PATTERN = re.compile(
    r"\bdocker\s+(run|pull|create|build)\b[^\n]*\b[a-zA-Z0-9][\w./-]*:latest\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"^\s*(?:@)?\s*(?:-)?\s*(curl|wget|eval|exec)\b",
    re.IGNORECASE,
)


@dataclass
class MakefileFinding:
    """A security or best-practice issue in a Makefile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    target: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        target = f" ({self.target})" if self.target else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{target} — {self.message}"


@dataclass
class MakefileTargetInfo:
    """Parsed metadata about a Makefile target."""

    name: str
    lineno: int
    is_phony: bool = False
    recipe_lines: int = 0


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[MakefileTargetInfo] = field(default_factory=list)
    has_phony: bool = False
    lines: int = 0


@dataclass
class MakefileStats:
    """Aggregate Makefile analysis statistics."""

    makefiles: int
    findings: int
    targets: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_makefile(path: Path) -> bool:
    if path.name in MAKEFILE_NAMES:
        return True
    # Extension-based Makefiles (e.g. Makefile.docker)
    if path.name.startswith("Makefile.") or path.name.endswith(".mk"):
        return True
    return False


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, dangerous ``rm -rf`` patterns, ``sudo`` usage,
  hardcoded secrets, force-push git commands, insecure TLS flags, privileged
    Docker runs, and unpinned ``:latest`` image tags.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MakefileFinding] | None = None
        self._stats: MakefileStats | None = None
        self._infos: list[MakefileInfo] | None = None

    def makefiles(self) -> list[Path]:
        """Return Makefile paths found in the project."""
        found: list[Path] = []
        for name in MAKEFILE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_makefile(path) and path not in found:
                if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
                    continue
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], MakefileInfo]:
        findings: list[MakefileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MakefileInfo(path=rel)

        info = MakefileInfo(path=rel, lines=len(raw_lines))
        phony_targets: set[str] = set()
        current_target = ""
        current_target_lineno = 0
        in_recipe = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith(".PHONY:"):
                info.has_phony = True
                for target in line.split(":", 1)[1].split():
                    phony_targets.add(target.strip())
                continue

            if line.startswith(".PHONY "):
                info.has_phony = True
                for target in line.split()[1:]:
                    phony_targets.add(target.strip())
                continue

            if ":" in line and not line.startswith("\t") and not raw.startswith("\t"):
                if not line.startswith(".") or line.startswith(".DEFAULT"):
                    target_name = line.split(":", 1)[0].strip()
                    if target_name and not target_name.startswith("."):
                        current_target = target_name
                        current_target_lineno = lineno
                        in_recipe = False
                        info.targets.append(
                            MakefileTargetInfo(
                                name=target_name,
                                lineno=lineno,
                                is_phony=target_name in phony_targets,
                            )
                        )
                continue

            if raw.startswith("\t") or raw.startswith(" " * 4):
                in_recipe = True
                if info.targets:
                    info.targets[-1].recipe_lines += 1

                recipe = line.lstrip("@-")
                if CURL_PIPE_SHELL_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="recipe pipes curl/wget to shell — supply-chain risk",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if DANGEROUS_RM_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="dangerous_rm",
                            severity="high",
                            message="recipe uses dangerous rm pattern — risk of deleting system paths",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if SUDO_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="sudo_usage",
                            severity="medium",
                            message="recipe uses sudo — avoid elevated privileges in build scripts",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if CHMOD_777_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="chmod_777",
                            severity="high",
                            message="recipe sets world-writable permissions (chmod 777)",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if CHMOD_SETUID_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="chmod_setuid",
                            severity="high",
                            message="recipe sets setuid/setgid bits — security risk",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if EVAL_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="eval_usage",
                            severity="high",
                            message="recipe uses eval — arbitrary code execution risk",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if FORCE_PUSH_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="force_push",
                            severity="medium",
                            message="recipe runs git push --force — can overwrite remote history",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if INSECURE_CURL_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="insecure_curl",
                            severity="medium",
                            message="recipe disables TLS verification in curl",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if INSECURE_WGET_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="insecure_wget",
                            severity="medium",
                            message="recipe disables TLS verification in wget",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if PRIVILEGED_DOCKER_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="privileged_docker",
                            severity="high",
                            message="recipe runs Docker with --privileged — container escape risk",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if UNPINNED_DOCKER_IMAGE_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="unpinned_docker_image",
                            severity="low",
                            message="recipe uses unpinned :latest Docker image tag",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )
                if DANGEROUS_SHELL_PATTERN.search(recipe):
                    findings.append(
                        MakefileFinding(
                            kind="dangerous_command",
                            severity="medium",
                            message="recipe starts with a potentially dangerous command — review carefully",
                            path=rel,
                            lineno=lineno,
                            target=current_target,
                            line=raw.strip(),
                        )
                    )

            if SECRET_PATTERN.search(line):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="potential secret hardcoded in Makefile — use environment variables",
                        path=rel,
                        lineno=lineno,
                        target=current_target,
                        line=raw.strip(),
                    )
                )

        for target_info in info.targets:
            target_info.is_phony = target_info.name in phony_targets
            if not info.has_phony and target_info.recipe_lines > 0 and not target_info.is_phony:
                if target_info.name in {"clean", "install", "test", "build", "deploy", "lint", "format"}:
                    findings.append(
                        MakefileFinding(
                            kind="missing_phony",
                            severity="low",
                            message=f"target '{target_info.name}' should be declared .PHONY",
                            path=rel,
                            lineno=target_info.lineno,
                            target=target_info.name,
                            line="",
                        )
                    )

        return findings, info

    def analyze(self) -> list[MakefileFinding]:
        """Scan Makefiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MakefileFinding] = []
        infos: list[MakefileInfo] = []
        paths = self.makefiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_targets = sum(len(i.targets) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = MakefileStats(
            makefiles=len(paths),
            findings=len(findings),
            targets=total_targets,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MakefileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MakefileInfo]:
        """Return parsed Makefile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Makefiles)."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Makefile template."""
        return """\
# Generated by DevAI MakefileAnalyzer
.PHONY: help install test lint clean

help:
\t@echo "Available targets: install test lint clean"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check src tests

clean:
\trm -rf build dist *.egg-info .pytest_cache .ruff_cache
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefiles: none found"
        return (
            f"Makefiles: {stats.makefiles} file(s), {stats.targets} target(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Makefile analysis:",
            f"  makefiles: {stats.makefiles}",
            f"  targets: {stats.targets}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.targets)} target(s)")
            for target in info.targets[:10]:
                phony = " (phony)" if target.is_phony else ""
                lines.append(f"      {target.name}{phony}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
