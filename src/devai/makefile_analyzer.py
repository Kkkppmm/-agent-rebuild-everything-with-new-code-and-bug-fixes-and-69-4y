"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile")
MAKEFILE_SUFFIXES = (".mk", ".mak")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b")
RM_RF_DANGEROUS_PATTERN = re.compile(
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?(/|\*|~\s*/|\$\(HOME\))",
    re.IGNORECASE,
)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b")
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(eval|exec)\s+")
DOCKER_LATEST_PATTERN = re.compile(r"\b(docker\s+pull|image:\s*)[^\s:]+:latest\b", re.IGNORECASE)
DOCKER_PRIVILEGED_PATTERN = re.compile(r"(?:^|\s)--privileged(?:\s|$)")
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b[^\n]*--force\b|\bgit\s+push\s+-f\b")
DANGEROUS_WILDCARD_PATTERN = re.compile(r"\b(find|chmod|chown)\b[^\n]*\*")
COMMON_TARGETS = frozenset({"clean", "install", "test", "build", "deploy", "release", "all"})


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
        loc = f"{self.path}:{self.lineno}"
        if self.target:
            loc += f" ({self.target})"
        return f"[{self.severity}] {loc} — {self.message}"


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
    has_phony_decl: bool = False
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
    name = path.name
    if name in MAKEFILE_NAMES:
        return True
    lower = name.lower()
    return lower.endswith(MAKEFILE_SUFFIXES)


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for curl-pipe-to-shell, dangerous ``rm -rf``, hardcoded secrets,
    ``sudo`` usage, ``chmod 777``, privileged Docker flags, force-pushes,
    and missing ``.PHONY`` declarations for common targets.
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
                if any(part.startswith(".") and part not in (".", "..") for part in path.parts):
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
        current_target: MakefileTargetInfo | None = None
        in_recipe = False

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue

            is_recipe_line = raw.startswith(("\t", " ")) and stripped

            if stripped.startswith(".PHONY:"):
                info.has_phony_decl = True
                targets_part = stripped.split(":", 1)[1].strip()
                for target in targets_part.split():
                    phony_targets.add(target)
                    for t in info.targets:
                        if t.name == target:
                            t.is_phony = True
                in_recipe = False
                continue

            if stripped.startswith(".PHONY "):
                info.has_phony_decl = True
                for target in stripped.split()[1:]:
                    phony_targets.add(target)
                    for t in info.targets:
                        if t.name == target:
                            t.is_phony = True
                in_recipe = False
                continue

            if (
                not is_recipe_line
                and re.match(r"^[a-zA-Z0-9_.-]+(\s+[a-zA-Z0-9_.-]+)*\s*:", stripped)
                and not stripped.startswith("\t")
            ):
                if stripped.startswith(".") and not stripped.startswith(".PHONY"):
                    in_recipe = False
                    continue
                target_name = stripped.split(":", 1)[0].strip().split()[0]
                current_target = MakefileTargetInfo(
                    name=target_name,
                    lineno=lineno,
                    is_phony=target_name in phony_targets,
                )
                info.targets.append(current_target)
                in_recipe = True
                continue

            if not is_recipe_line:
                in_recipe = False
                continue

            recipe = stripped
            target_name = current_target.name if current_target else ""

            if current_target is not None:
                current_target.recipe_lines += 1

            if CURL_PIPE_SHELL_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="recipe pipes curl/wget to shell — supply-chain risk",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if SUDO_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="recipe uses sudo — prefer non-privileged build steps",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if RM_RF_DANGEROUS_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="dangerous_rm",
                        severity="high",
                        message="recipe uses dangerous rm -rf on broad path — risk of data loss",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if CHMOD_777_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="chmod_777",
                        severity="medium",
                        message="recipe sets world-writable permissions (chmod 777)",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if SECRET_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="secret_in_makefile",
                        severity="high",
                        message="potential secret hardcoded in Makefile — use env vars",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if EVAL_EXEC_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="eval_exec",
                        severity="high",
                        message="recipe uses eval/exec — review for command injection",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if DOCKER_LATEST_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="docker_latest",
                        severity="medium",
                        message="recipe uses :latest Docker tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if DOCKER_PRIVILEGED_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="docker_privileged",
                        severity="high",
                        message="recipe runs Docker with --privileged — avoid in build scripts",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if FORCE_PUSH_PATTERN.search(recipe):
                findings.append(
                    MakefileFinding(
                        kind="force_push",
                        severity="high",
                        message="recipe includes git force-push — risk of overwriting remote history",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

            if DANGEROUS_WILDCARD_PATTERN.search(recipe) and "node_modules" not in recipe:
                findings.append(
                    MakefileFinding(
                        kind="dangerous_wildcard",
                        severity="medium",
                        message="recipe applies command to broad wildcard — verify scope",
                        path=rel,
                        lineno=lineno,
                        target=target_name,
                        line=recipe,
                    )
                )

        for target in info.targets:
            if target.name in COMMON_TARGETS and not target.is_phony and not info.has_phony_decl:
                findings.append(
                    MakefileFinding(
                        kind="missing_phony",
                        severity="low",
                        message=f"common target '{target.name}' should be declared in .PHONY",
                        path=rel,
                        lineno=target.lineno,
                        target=target.name,
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
.PHONY: help install test lint clean build

help:  ## Show available targets
\t@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\\n", $$1, $$2}'

install:  ## Install dependencies
\tpython -m pip install -e ".[dev]"

test:  ## Run test suite
\tpython -m pytest

lint:  ## Run linters
\truff check .

clean:  ## Remove build artifacts
\trm -rf build dist .pytest_cache .ruff_cache
\tfind . -type d -name __pycache__ -exec rm -rf {} +

build:  ## Build distribution packages
\tpython -m build
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
                phony = "phony" if target.is_phony else "file"
                lines.append(f"      {target.name} ({phony}, {target.recipe_lines} recipe line(s))")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
