"""TravisCIAnalyzer — audit Travis CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TRAVIS_FILENAMES = (".travis.yml", ".travis.yaml")

SUDO_ENABLED_PATTERN = re.compile(r"^\s*sudo\s*:\s*(true|required)\s*$", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
UNPINNED_DOCKER_IMAGE_PATTERN = re.compile(
    r"^\s*-\s*image:\s*(?!.*:)[a-z0-9][a-z0-9._/-]*\s*$",
    re.IGNORECASE,
)
MUTABLE_DOCKER_TAG_PATTERN = re.compile(
    r"^\s*-\s*image:\s*[^:]+:(latest|stable|nightly|dev|main|master)\s*$",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"privileged\s*:\s*true\b", re.IGNORECASE)
TRAVIS_INSTALL_SCRIPT_PATTERN = re.compile(
    r"(travis-ci\.org|raw\.githubusercontent\.com/.+/travis)",
    re.IGNORECASE,
)
DEPRECATED_TRAVIS_PATTERN = re.compile(r"^\s*travis\s*:\s*true\s*$", re.IGNORECASE)
ALLOW_FAILURE_SECRETS_PATTERN = re.compile(
    r"^\s*allow_failure\s*:\s*true\b",
    re.IGNORECASE,
)


@dataclass
class TravisCIFinding:
    """A security or best-practice issue in a Travis CI config."""

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
class TravisCIInfo:
    """Parsed metadata about a Travis CI config file."""

    path: str
    language: str = ""
    branches: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    uses_docker: bool = False
    lines: int = 0


@dataclass
class TravisCIStats:
    """Aggregate Travis CI analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_travis_file(path: Path) -> bool:
    return path.name.lower() in TRAVIS_FILENAMES


class TravisCIAnalyzer:
    """Audit Travis CI configuration files for security risks and CI best practices.

    Scans for sudo usage, hardcoded secrets, curl-pipe-to-shell scripts,
    unpinned Docker images, privileged containers, and deprecated Travis settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TravisCIFinding] | None = None
        self._stats: TravisCIStats | None = None
        self._infos: list[TravisCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Travis CI config file paths found in the project."""
        found: list[Path] = []
        for name in TRAVIS_FILENAMES:
            direct = self.root / name
            if direct.is_file():
                found.append(direct)
        for path in sorted(self.root.rglob(".travis/*")):
            if path.is_file() and path.suffix.lower() in (".yml", ".yaml"):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TravisCIFinding], TravisCIInfo]:
        findings: list[TravisCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TravisCIInfo(path=rel)

        info = TravisCIInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        env_indent = 0
        in_branches_only = False
        in_matrix = False
        current_job: str | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("language:"):
                info.language = line.split(":", 1)[1].strip()

            if line == "docker:" or line.startswith("docker:"):
                info.uses_docker = True

            if line.startswith("branches:"):
                in_branches_only = True
                continue

            if in_branches_only and line.startswith("- "):
                branch = line[2:].strip()
                if branch:
                    info.branches.append(branch)
                continue

            if line.startswith("matrix:") or line.startswith("jobs:"):
                in_matrix = True
                in_branches_only = False

            if in_matrix and re.match(r"^\s*-\s*name:\s*", raw):
                current_job = raw.split("name:", 1)[1].strip()
                if current_job:
                    info.jobs.append(current_job)

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key == "env":
                    in_env_block = True
                    env_indent = len(raw) - len(raw.lstrip())
                elif key in ("matrix", "include", "services", "addons", "script", "install"):
                    in_env_block = False
                if key in ("matrix", "jobs"):
                    in_matrix = True
                    in_branches_only = False
                if key not in ("only", "except", "global"):
                    in_branches_only = False

            if SUDO_ENABLED_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="sudo_enabled",
                        severity="medium",
                        message="sudo enabled — Travis workers already have sudo; avoid broad sudo usage",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DEPRECATED_TRAVIS_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="deprecated_travis",
                        severity="low",
                        message="travis: true is deprecated — Travis CI is discontinued; migrate to GitHub Actions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker service grants full host access to the build",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_DOCKER_IMAGE_PATTERN.match(line) or MUTABLE_DOCKER_TAG_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="unpinned_docker_image",
                        severity="medium",
                        message="Docker service image unpinned or uses mutable tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env_block and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent and "secure:" not in line.lower():
                    findings.append(
                        TravisCIFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in env — use Travis encrypted variables",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("- ") or line.startswith("script:") or " && " in line:
                script_line = line if line.startswith("script:") else line
                if CURL_PIPE_SHELL_PATTERN.search(script_line):
                    findings.append(
                        TravisCIFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in Travis script is unsafe",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if TRAVIS_INSTALL_SCRIPT_PATTERN.search(script_line):
                    findings.append(
                        TravisCIFinding(
                            kind="untrusted_install_script",
                            severity="medium",
                            message="installing from external Travis script URL — verify source integrity",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if ALLOW_FAILURE_SECRETS_PATTERN.match(line) and in_env_block:
                findings.append(
                    TravisCIFinding(
                        kind="allow_failure_env",
                        severity="low",
                        message="allow_failure on env matrix may hide secret-related build failures",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[TravisCIFinding]:
        """Scan Travis CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TravisCIFinding] = []
        infos: list[TravisCIInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TravisCIStats(
            configs=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TravisCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TravisCIInfo]:
        """Return parsed Travis CI metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
        """Scaffold a hardened Travis CI configuration template."""
        return """\
# Generated by DevAI TravisCIAnalyzer
# Note: Travis CI is discontinued — prefer GitHub Actions for new projects.
language: python
python:
  - "3.12"
sudo: false
branches:
  only:
    - main
env:
  global:
    - PIP_DISABLE_PIP_VERSION_CHECK=1
install:
  - pip install -e ".[dev]"
script:
  - python -m pytest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Travis CI: none found"
        return (
            f"Travis CI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Travis CI analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lang = info.language or "unknown"
            lines.append(
                f"  - {info.path}: language={lang}, docker={info.uses_docker}, "
                f"jobs={len(info.jobs)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
