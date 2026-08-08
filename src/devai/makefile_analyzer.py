"""MakefileAnalyzer — audit Makefiles for security risks and build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAKEFILE_NAMES = ("Makefile", "makefile", "GNUmakefile", "GNUMakefile")
MAKEFILE_SUFFIXES = (".mk",)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_RM_PATTERN = re.compile(
    r"\brm\s+.*(-[a-zA-Z]*f[a-zA-Z]*\s+|-[a-zA-Z]*r[a-zA-Z]*\s+).*(/\s*$|/\*|~|/\.\.|/\$)",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+/\b", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=+?]?=\s*['\"]?[^\s'\"#]{4,}",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"\bchmod\s+777\b", re.IGNORECASE)
CHMOD_WORLD_WRITABLE_PATTERN = re.compile(r"\bchmod\s+[a-zA-Z]*[2367][a-zA-Z]*\b")
EVAL_PATTERN = re.compile(r"\beval\b", re.IGNORECASE)
FORCE_PUSH_PATTERN = re.compile(r"\bgit\s+push\b[^;\n]*--force\b", re.IGNORECASE)
LATEST_DOCKER_PATTERN = re.compile(r"\bdocker\s+(run|pull|build)\b[^;\n]*:latest\b", re.IGNORECASE)
DD_DEVICE_PATTERN = re.compile(r"\bdd\s+.*\bof=/dev/", re.IGNORECASE)
CURL_INSECURE_PATTERN = re.compile(r"\bcurl\b[^;\n]*\s(-k|--insecure)\b", re.IGNORECASE)
TARGET_PATTERN = re.compile(r"^([a-zA-Z0-9_.-]+)\s*:(?!=)")
PHONY_PATTERN = re.compile(r"^\.PHONY\s*:")
COMMON_PHONY_TARGETS = frozenset(
    {"all", "clean", "test", "install", "build", "run", "lint", "format", "check", "deploy"}
)


@dataclass
class MakefileFinding:
    """A security or best-practice issue in a Makefile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MakefileTargetInfo:
    """Parsed metadata about a Makefile target."""

    name: str
    is_phony: bool = False
    recipe_lines: int = 0


@dataclass
class MakefileInfo:
    """Parsed metadata about a Makefile."""

    path: str
    targets: list[MakefileTargetInfo] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
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
    name = path.name
    lower = name.lower()
    if name in MAKEFILE_NAMES or lower in (n.lower() for n in MAKEFILE_NAMES):
        return True
    if lower.endswith(MAKEFILE_SUFFIXES):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class MakefileAnalyzer:
    """Audit Makefiles for security risks and build best practices.

    Scans for dangerous ``rm`` patterns, curl-pipe-to-shell, hardcoded secrets,
    ``sudo`` usage, permissive ``chmod``, ``eval``, force-push git commands,
    unpinned Docker images, and missing ``.PHONY`` declarations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MakefileFinding] | None = None
        self._stats: MakefileStats | None = None
        self._infos: list[MakefileInfo] | None = None

    def makefiles(self) -> list[Path]:
        """Return Makefile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_makefile(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[MakefileFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        raw: str,
    ) -> None:
        findings.append(
            MakefileFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=raw.strip(),
            )
        )

    def _check_recipe_line(
        self,
        findings: list[MakefileFinding],
        line: str,
        rel: str,
        lineno: int,
        raw: str,
    ) -> None:
        if CURL_PIPE_SHELL_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="curl_pipe_shell",
                severity="high",
                message="recipe pipes curl/wget to shell — supply-chain risk",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if RM_RF_ROOT_PATTERN.search(line) or DANGEROUS_RM_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="dangerous_rm",
                severity="high",
                message="recipe uses dangerous rm -rf pattern — risk of data loss",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if EVAL_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="eval_usage",
                severity="high",
                message="recipe uses eval — arbitrary code execution risk",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if DD_DEVICE_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="dd_device",
                severity="high",
                message="recipe writes to block device with dd — destructive operation",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if SECRET_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="secret_in_makefile",
                severity="high",
                message="potential secret hardcoded in Makefile — use env vars or .env",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if SUDO_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="sudo_usage",
                severity="medium",
                message="recipe uses sudo — prefer non-privileged build steps",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if CHMOD_777_PATTERN.search(line) or CHMOD_WORLD_WRITABLE_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="chmod_permissive",
                severity="medium",
                message="recipe sets world-writable permissions — use least privilege",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if FORCE_PUSH_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="force_push",
                severity="medium",
                message="recipe uses git push --force — risk of overwriting remote history",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if LATEST_DOCKER_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="latest_docker_tag",
                severity="low",
                message="docker command uses :latest tag — pin a specific version",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )
        if CURL_INSECURE_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="curl_insecure",
                severity="medium",
                message="curl uses -k/--insecure — TLS verification disabled",
                rel=rel,
                lineno=lineno,
                raw=raw,
            )

    def _analyze_file(self, path: Path) -> tuple[list[MakefileFinding], MakefileInfo]:
        findings: list[MakefileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MakefileInfo(path=rel)

        info = MakefileInfo(path=rel, lines=len(raw_lines))
        phony_targets: set[str] = set()
        declared_targets: dict[str, MakefileTargetInfo] = {}
        current_target: str | None = None
        continuation = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.endswith("\\"):
                continuation = (continuation + " " + line[:-1]).strip()
                continue

            if continuation:
                line = (continuation + " " + line).strip()
                continuation = ""

            if PHONY_PATTERN.match(line):
                info.has_phony = True
                phony_part = line.split(":", 1)[1].strip()
                for target in phony_part.split():
                    phony_targets.add(target)
                    if target in declared_targets:
                        declared_targets[target].is_phony = True
                continue

            target_match = TARGET_PATTERN.match(line)
            if target_match and not line.startswith("\t") and not raw.startswith("\t"):
                target_name = target_match.group(1)
                if target_name not in declared_targets:
                    declared_targets[target_name] = MakefileTargetInfo(
                        name=target_name,
                        is_phony=target_name in phony_targets,
                    )
                current_target = target_name
                continue

            if raw.startswith("\t") or raw.startswith(" " * 4):
                recipe = line
                if current_target and current_target in declared_targets:
                    declared_targets[current_target].recipe_lines += 1
                self._check_recipe_line(findings, recipe, rel, lineno, raw)
                continue

            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*(:=|[?:]?=)", line):
                var_name = re.split(r"\s*(:=|[?:]?=)", line, maxsplit=1)[0].strip()
                info.variables.append(var_name)
                if SECRET_PATTERN.search(line):
                    self._add_finding(
                        findings,
                        kind="secret_in_makefile",
                        severity="high",
                        message=f"variable '{var_name}' may contain a hardcoded secret",
                        rel=rel,
                        lineno=lineno,
                        raw=raw,
                    )

        for target_name, target_info in declared_targets.items():
            info.targets.append(target_info)
            if (
                target_name in COMMON_PHONY_TARGETS
                and not target_info.is_phony
                and not info.has_phony
            ):
                findings.append(
                    MakefileFinding(
                        kind="missing_phony",
                        severity="low",
                        message=f"target '{target_name}' should be declared .PHONY",
                        path=rel,
                        lineno=0,
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
.PHONY: all clean test lint install

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

all: test

test:
\tpython -m pytest

lint:
\truff check .

clean:
\trm -rf build dist .pytest_cache __pycache__

install:
\tpip install -e .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.makefiles == 0:
            return "Makefile: no Makefiles found"
        return (
            f"Makefile: {stats.makefiles} file(s), {stats.targets} target(s), "
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
            target_names = ", ".join(t.name for t in info.targets[:8]) or "none"
            lines.append(f"  - {info.path}: {len(info.targets)} target(s) [{target_names}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
