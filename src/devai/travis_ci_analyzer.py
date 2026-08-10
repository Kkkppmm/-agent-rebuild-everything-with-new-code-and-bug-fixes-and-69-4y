"""TravisCIAnalyzer — audit Travis CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TRAVIS_CI_NAMES = (".travis.yml", ".travis.yaml")

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
UNENCRYPTED_SECRET_PATTERN = re.compile(
    r"^\s*-\s*(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*=",
    re.IGNORECASE,
)
DEPLOY_SKIP_CLEANUP_PATTERN = re.compile(
    r"skip_cleanup:\s*true\b",
    re.IGNORECASE,
)
ALLOW_FAILURE_PATTERN = re.compile(
    r"allow_failure:\s*true\b",
    re.IGNORECASE,
)
UNPINNED_LANGUAGE_PATTERN = re.compile(
    r"^\s*-\s*(python|node|ruby|go|java)\s*$",
    re.IGNORECASE,
)
SERVICES_LATEST_PATTERN = re.compile(
    r"services:\s*$|^\s*-\s*docker\b",
    re.IGNORECASE,
)
DEPLOY_PROVIDER_PATTERN = re.compile(
    r"provider:\s*(script|custom)\b",
    re.IGNORECASE,
)
INSECURE_GIT_DEPTH_PATTERN = re.compile(
    r"git:\s*$|depth:\s*false\b",
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
    dist: str = ""
    stages: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TravisCIStats:
    """Aggregate Travis CI analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_travis_ci_file(path: Path) -> bool:
    return path.name.lower() in TRAVIS_CI_NAMES


class TravisCIAnalyzer:
    """Audit Travis CI configs for security risks and CI best practices.

    Scans for secrets in environment blocks, curl-pipe-to-shell patterns,
    sudo usage in scripts, unencrypted env vars, deploy skip_cleanup, and
    unpinned language versions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TravisCIFinding] | None = None
        self._stats: TravisCIStats | None = None
        self._infos: list[TravisCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Travis CI config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_travis_ci_file(path):
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
        in_env = False
        in_global_env = False
        in_script = False
        in_install = False
        in_deploy = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("language:"):
                info.language = line.split(":", 1)[1].strip().strip("'\"")

            if line.startswith("dist:"):
                info.dist = line.split(":", 1)[1].strip().strip("'\"")

            if line.startswith("stages:"):
                in_env = False
                in_script = False
                in_deploy = False
                continue

            if line.startswith("- ") and not in_script and not in_env:
                stage = line[2:].strip().rstrip(":")
                if stage and not stage.startswith("#"):
                    if stage not in info.stages:
                        info.stages.append(stage)

            if line.startswith("env:") or line == "global:":
                in_env = True
                in_global_env = line.startswith("global:") or line == "global:"
                env_indent = len(raw) - len(raw.lstrip())
                in_script = False
                in_deploy = False
                continue

            if in_env and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent or line.startswith("- "):
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

            if in_env and UNENCRYPTED_SECRET_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="unencrypted_secret",
                        severity="high",
                        message="sensitive env var name without encryption — use travis encrypt",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("install:"):
                in_install = True
                in_script = False
                in_env = False
                in_deploy = False
                continue

            if line.startswith("script:") or line.startswith("before_script:") or line.startswith("after_script:"):
                in_script = True
                in_install = False
                in_env = False
                in_deploy = False
                continue

            if line.startswith("deploy:"):
                in_deploy = True
                in_script = False
                in_install = False
                in_env = False
                continue

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("jobs", "include", "matrix", "services", "addons", "cache"):
                    in_script = False
                    in_install = False
                    in_env = False
                if key == "jobs":
                    in_deploy = False

            if UNPINNED_LANGUAGE_PATTERN.match(line) and info.language:
                findings.append(
                    TravisCIFinding(
                        kind="unpinned_language",
                        severity="low",
                        message=f"unpinned {info.language} version in matrix — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("- docker") or (line == "docker" and SERVICES_LATEST_PATTERN.search(line)):
                info.services.append("docker")

            if in_script or in_install or (line.startswith("- ") and not in_env):
                script_text = line
                if CURL_PIPE_SHELL_PATTERN.search(script_text):
                    findings.append(
                        TravisCIFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in script is unsafe",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if SUDO_PATTERN.search(script_text):
                    findings.append(
                        TravisCIFinding(
                            kind="sudo_usage",
                            severity="medium",
                            message="sudo in script — prefer container-based builds without elevated privileges",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if DEPLOY_SKIP_CLEANUP_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="deploy_skip_cleanup",
                        severity="medium",
                        message="deploy skip_cleanup: true leaves build artifacts on the runner",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_deploy and DEPLOY_PROVIDER_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="custom_deploy",
                        severity="medium",
                        message="custom/script deploy provider — audit deploy scripts for injection risks",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_FAILURE_PATTERN.search(line):
                findings.append(
                    TravisCIFinding(
                        kind="allow_failure",
                        severity="low",
                        message="allow_failure: true — ensure security checks are not marked as optional",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_GIT_DEPTH_PATTERN.search(line) and "depth:" in line.lower():
                findings.append(
                    TravisCIFinding(
                        kind="shallow_clone_disabled",
                        severity="low",
                        message="git depth: false fetches full history — may expose sensitive commits",
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
        """Scaffold a hardened Travis CI config template."""
        return """\
# Generated by DevAI TravisCIAnalyzer
language: python
dist: jammy
python:
  - "3.12"

install:
  - pip install -e ".[dev]"

script:
  - python -m pytest

# Use travis encrypt for secrets — never commit plaintext credentials
# env:
#   global:
#     - secure: "encrypted-value-here"
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
            "Travis CI config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: language={info.language or 'unknown'}, "
                f"dist={info.dist or 'unknown'}, stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
