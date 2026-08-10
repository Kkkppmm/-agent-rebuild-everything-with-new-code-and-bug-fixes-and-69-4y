"""TravisCIAnalyzer — audit Travis CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (".travis.yml", ".travis.yaml")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"\b(eval|exec)\b",
    re.IGNORECASE,
)
UNPINNED_PYTHON_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(python|node|ruby|go)\s*$",
    re.IGNORECASE,
)
DEPLOY_SSH_PATTERN = re.compile(
    r"deploy:\s*$|^\s*provider:\s*ssh",
    re.IGNORECASE,
)
UNSAFE_BRANCH_PATTERN = re.compile(
    r"^\s*only:\s*$|^\s*-\s*(master|main)\s*$",
    re.IGNORECASE,
)
PR_ONLY_PATTERN = re.compile(r"^\s*pull_request:\s*$", re.IGNORECASE)
SKIP_PR_PATTERN = re.compile(r"^\s*pull_request:\s*false\b", re.IGNORECASE)


@dataclass
class TravisFinding:
    """A security or best-practice issue in a Travis CI config file."""

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
class TravisInfo:
    """Parsed metadata about a Travis CI config file."""

    path: str
    language: str | None = None
    has_matrix: bool = False
    has_deploy: bool = False
    branches: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TravisStats:
    """Aggregate Travis CI config analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class TravisCIAnalyzer:
    """Audit Travis CI configuration files for security risks and best practices.

    Scans for secrets in env blocks, curl-pipe-to-shell install scripts, sudo
    usage, unpinned language versions, unsafe deploy configurations, and
    missing pull_request guards.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TravisFinding] | None = None
        self._stats: TravisStats | None = None
        self._infos: list[TravisInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Travis CI config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TravisFinding], TravisInfo]:
        findings: list[TravisFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TravisInfo(path=rel)

        info = TravisInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        env_indent = 0
        in_deploy = False
        deploy_indent = 0
        in_branches = False
        branches_indent = 0
        in_script_section = False
        script_indent = 0
        has_pull_request_section = False
        skip_pull_request = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("language:"):
                info.language = line.split(":", 1)[1].strip()

            if line == "matrix:" or line.startswith("matrix:"):
                info.has_matrix = True

            if line.startswith("deploy:") or line == "deploy:":
                info.has_deploy = True
                in_deploy = True
                deploy_indent = len(raw) - len(raw.lstrip())
                continue

            if in_deploy:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= deploy_indent and not line.startswith("deploy"):
                    in_deploy = False
                if DEPLOY_SSH_PATTERN.search(line):
                    findings.append(
                        TravisFinding(
                            kind="ssh_deploy",
                            severity="medium",
                            message="SSH deploy provider — ensure deploy keys have minimal scope",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("branches:") or line == "branches:":
                in_branches = True
                branches_indent = len(raw) - len(raw.lstrip())
                continue

            if in_branches:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= branches_indent and not line.startswith("branches"):
                    in_branches = False
                elif line.startswith("- "):
                    branch = line[2:].strip()
                    info.branches.append(branch)

            if line.startswith("env:") or line == "env:":
                in_env_block = True
                env_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline:
                    in_env_block = False
                continue

            if in_env_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent and not line.startswith("env"):
                    in_env_block = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        TravisFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in env — use Travis encrypted variables",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if SECRET_ENV_PATTERN.search(line) and not in_env_block:
                findings.append(
                    TravisFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in Travis config — use encrypted env vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("script:") or line == "script:":
                in_script_section = True
                script_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline and DANGEROUS_SCRIPT_PATTERN.search(line):
                    findings.append(
                        TravisFinding(
                            kind="dangerous_script",
                            severity="high",
                            message="Travis script step uses eval/exec — review for injection risk",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if inline:
                    in_script_section = False
                continue

            if in_script_section:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= script_indent and not line.startswith("script"):
                    in_script_section = False
                elif DANGEROUS_SCRIPT_PATTERN.search(line):
                    findings.append(
                        TravisFinding(
                            kind="dangerous_script",
                            severity="high",
                            message="Travis script step uses eval/exec — review for injection risk",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TravisFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in Travis script is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(line):
                findings.append(
                    TravisFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in Travis script — prefer container-based builds without sudo",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_PYTHON_PATTERN.match(line):
                findings.append(
                    TravisFinding(
                        kind="unpinned_language",
                        severity="low",
                        message="unpinned language version in matrix — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PR_ONLY_PATTERN.match(line):
                has_pull_request_section = True

            if SKIP_PR_PATTERN.search(line):
                skip_pull_request = True

        if info.has_deploy and not has_pull_request_section:
            findings.append(
                TravisFinding(
                    kind="deploy_without_pr_guard",
                    severity="medium",
                    message="deploy section without pull_request guard — restrict deploy to protected branches",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        if skip_pull_request:
            findings.append(
                TravisFinding(
                    kind="skip_pull_request",
                    severity="low",
                    message="pull_request: false — PRs will not be tested",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TravisFinding]:
        """Scan Travis CI config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TravisFinding] = []
        infos: list[TravisInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TravisStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TravisStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TravisInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
language: python

python:
  - "3.12"

cache:
  pip: true

install:
  - pip install -e ".[dev]"

script:
  - python -m pytest

branches:
  only:
    - main

pull_request:
  branches:
    - main
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Travis CI: no config files found"
        return (
            f"Travis CI: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Travis CI configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lang = info.language or "unknown"
            lines.append(
                f"  - {info.path}: language={lang}, deploy={info.has_deploy}, "
                f"matrix={info.has_matrix}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
