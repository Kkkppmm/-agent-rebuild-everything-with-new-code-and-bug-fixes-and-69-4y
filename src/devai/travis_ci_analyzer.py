"""TravisCIAnalyzer — audit Travis CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TRAVIS_NAMES = (".travis.yml", ".travis.yaml")

SECRET_ENV_PATTERN = re.compile(
    r"^\s*-\s*(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*=",
    re.IGNORECASE,
)
PLAIN_SECRET_PATTERN = re.compile(
    r"^\s*-\s*[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*\s*=\s*(?:['\"][^'\"]{4,}['\"]|[^\s#]+)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SUDO_REQUIRED_PATTERN = re.compile(
    r"^\s*sudo:\s*(true|required)\s*$",
    re.IGNORECASE,
)
DEPLOY_API_KEY_PATTERN = re.compile(
    r"api_key:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
DEPLOY_ALL_BRANCHES_PATTERN = re.compile(
    r"^\s*all_branches:\s*true\b",
    re.IGNORECASE,
)
LATEST_DOCKER_PATTERN = re.compile(
    r"^\s*-\s*name:\s*[^\n]+\n\s*image:\s*[^\s]+:latest\b",
    re.IGNORECASE | re.MULTILINE,
)
FLOATING_NODE_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(node|stable|lts)['\"]?\s*$",
    re.IGNORECASE,
)
FLOATING_PYTHON_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(development|nightly)['\"]?\s*$",
    re.IGNORECASE,
)
UNQUOTED_VAR_SCRIPT_PATTERN = re.compile(
    r"^\s*-\s*.*\$TRAVIS_(PULL_REQUEST_BRANCH|BRANCH|COMMIT_MESSAGE)\b",
    re.IGNORECASE,
)
DEPLOY_PROVIDER_PATTERN = re.compile(r"^\s*provider:\s*", re.IGNORECASE)


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
    has_deploy: bool = False
    lines: int = 0


@dataclass
class TravisCIStats:
    """Aggregate Travis CI analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_travis_file(path: Path) -> bool:
    return path.name.lower() in TRAVIS_NAMES


class TravisCIAnalyzer:
    """Audit Travis CI configs for security risks and CI best practices.

    Scans for plaintext secrets in env, curl-pipe-to-shell install scripts,
    sudo requirements, unpinned language versions, unsafe deploy settings,
    and branch-filter misconfigurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TravisCIFinding] | None = None
        self._stats: TravisCIStats | None = None
        self._infos: list[TravisCIInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Travis CI config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_travis_file(path):
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
        content = "\n".join(raw_lines)
        in_env = False
        in_deploy = False
        deploy_indent = 0
        deploy_has_all_branches = False
        deploy_start_line = 0

        if LATEST_DOCKER_PATTERN.search(content):
            for lineno, raw in enumerate(raw_lines, start=1):
                if ":latest" in raw:
                    findings.append(
                        TravisCIFinding(
                            kind="latest_docker_service",
                            severity="medium",
                            message="Docker service uses :latest tag — pin to a specific version",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                    break

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("language:"):
                info.language = line.split(":", 1)[1].strip()

            if line == "env:" or line.startswith("env:"):
                in_env = True
                continue

            if line.startswith("branches:"):
                in_env = False

            if line.startswith("deploy:"):
                in_deploy = True
                info.has_deploy = True
                deploy_start_line = lineno
                deploy_indent = len(raw) - len(raw.lstrip())
                deploy_has_all_branches = False
                continue

            if in_deploy:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= deploy_indent and line and not line.startswith("#"):
                    if deploy_has_all_branches:
                        findings.append(
                            TravisCIFinding(
                                kind="deploy_all_branches",
                                severity="high",
                                message=(
                                    "deploy.all_branches: true can deploy untrusted PR branches"
                                ),
                                path=rel,
                                lineno=deploy_start_line,
                                line="deploy:",
                            )
                        )
                    in_deploy = False
                    deploy_has_all_branches = False

            if in_deploy and DEPLOY_ALL_BRANCHES_PATTERN.match(line):
                deploy_has_all_branches = True

            if in_deploy and DEPLOY_API_KEY_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="plaintext_deploy_key",
                        severity="high",
                        message="api_key hardcoded in deploy block — use encrypted env vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env and SECRET_ENV_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="secret_env_key",
                        severity="medium",
                        message="sensitive env var name in config — use Travis encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env and PLAIN_SECRET_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="plaintext_secret",
                        severity="high",
                        message="plaintext secret in env block — use secure: encrypted values",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("script:") or line.startswith("before_install:") or line.startswith(
                "install:"
            ):
                in_env = False

            if CURL_PIPE_SHELL_PATTERN.search(line):
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

            if SUDO_REQUIRED_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="sudo_required",
                        severity="medium",
                        message="sudo: true/required increases attack surface — avoid when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if info.language == "node_js" and FLOATING_NODE_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="floating_node_version",
                        severity="medium",
                        message="floating Node.js version (node/stable/lts) — pin a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if info.language == "python" and FLOATING_PYTHON_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="floating_python_version",
                        severity="medium",
                        message="floating Python version — pin a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("- ") and UNQUOTED_VAR_SCRIPT_PATTERN.match(line):
                findings.append(
                    TravisCIFinding(
                        kind="unquoted_travis_var",
                        severity="medium",
                        message=(
                            "unquoted Travis env var in script — quote variables to prevent injection"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("only:") or line.startswith("- "):
                branch_match = re.match(r"^\s*-\s*['\"]?([a-zA-Z0-9_./-]+)['\"]?\s*$", line)
                if branch_match and "branches" in raw_lines[max(0, lineno - 3) : lineno]:
                    info.branches.append(branch_match.group(1))

        if in_deploy and deploy_has_all_branches:
            findings.append(
                TravisCIFinding(
                    kind="deploy_all_branches",
                    severity="high",
                    message="deploy.all_branches: true can deploy untrusted PR branches",
                    path=rel,
                    lineno=deploy_start_line,
                    line="deploy:",
                )
            )

        return findings, info

    def analyze(self) -> list[TravisCIFinding]:
        """Scan Travis CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TravisCIFinding] = []
        infos: list[TravisCIInfo] = []
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
        self._stats = TravisCIStats(
            config_files=len(paths),
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

branches:
  only:
    - main

env:
  global:
    - CI=true

install:
  - pip install -e ".[dev]"

script:
  - python -m pytest

sudo: false
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Travis CI: no config found"
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
            "Travis CI analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            branches = ", ".join(info.branches[:5]) or "default"
            deploy = "yes" if info.has_deploy else "no"
            lines.append(
                f"  - {info.path}: language={info.language or 'unknown'}, "
                f"deploy={deploy}, branches=[{branches}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
