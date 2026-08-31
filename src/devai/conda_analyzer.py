"""CondaAnalyzer — audit Conda environment and recipe files for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONDA_ENV_NAMES = (
    "environment.yml",
    "environment.yaml",
    "conda.yml",
    "conda.yaml",
)
CONDA_LOCK_NAMES = (
    "conda-lock.yml",
    "conda-lock.yaml",
    "environment-lock.yml",
    "environment-lock.yaml",
)
CONDA_RECIPE_META = "meta.yaml"
CONDA_MARKER_PATTERN = re.compile(
    r"(?:^channels:|^dependencies:|^name:\s|conda-forge|anaconda\.com|"
    r"^package:\s*$|^build:\s*$|conda-build|conda env)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|anaconda[_-]?token|conda[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ANACONDA_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:conda|anaconda|pypi)-[A-Za-z0-9_-]{20,}[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"(?:=\s*[\"']?\*[\"']?|[=<>!~]+\s*[\"']?\*[\"']?|"
    r"[=<>!~]+\s*[\"']?latest[\"']?|"
    r"(?<![=<>!~])>=\s*[\"']?\d|(?<![=<>!~])<=\s*[\"']?\d|"
    r"(?<![=<>!~])>\s*[\"']?\d|(?<![=<>!~])<\s*[\"']?\d)",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:@main\b|@master\b|@HEAD\b|@develop\b|branch=main\b|branch=master\b)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:ssl_verify\s*[=:]\s*false|verify_ssl\s*[=:]\s*false|"
    r"insecure\s*[=:]\s*true|ssl-no-revoke|trusted-host\s*=)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
CHANNEL_PATTERN = re.compile(
    r"^\s*-\s*(https?://\S+|[\w.-]+/?)$",
    re.IGNORECASE,
)
DEPENDENCY_PATTERN = re.compile(
    r"^\s*-\s+([a-zA-Z0-9_.-]+)(?:[=<>!~].*)?$",
)
PIP_SECTION_PATTERN = re.compile(r"^\s*-\s*pip:\s*$", re.IGNORECASE)


@dataclass
class CondaFinding:
    """A security or best-practice issue in a Conda configuration file."""

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
class CondaInfo:
    """Parsed metadata about a Conda configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)


@dataclass
class CondaStats:
    """Aggregate Conda analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_conda_config(path: Path) -> bool:
    """Return True if the path looks like a Conda configuration file."""
    name = path.name.lower()
    if name in CONDA_ENV_NAMES or name in CONDA_LOCK_NAMES:
        return True
    if name == CONDA_RECIPE_META:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CONDA_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name in CONDA_ENV_NAMES:
        return "environment"
    if name in CONDA_LOCK_NAMES:
        return "lock"
    if name == CONDA_RECIPE_META:
        return "recipe"
    return "unknown"


class CondaAnalyzer:
    """Audit Conda environment and recipe files for security issues.

    Scans environment.yml, conda-lock files, and recipe meta.yaml for
    hardcoded Anaconda tokens, insecure HTTP channels, credentials in git
    URLs, unpinned dependencies, loose version constraints, disabled SSL
    verification, missing lockfiles, and curl-pipe-to-shell in build scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CondaFinding] | None = None
        self._stats: CondaStats | None = None
        self._infos: list[CondaInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Conda configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_conda_config(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CondaFinding], CondaInfo]:
        findings: list[CondaFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CondaInfo(path=rel)

        raw_lines = text.splitlines()
        info = CondaInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_dependencies = False
        in_pip_section = False
        in_channels = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            lower = stripped.lower()
            if lower == "channels:":
                in_channels = True
                in_dependencies = False
                in_pip_section = False
                continue
            if lower == "dependencies:":
                in_dependencies = True
                in_channels = False
                in_pip_section = False
                continue
            if lower.startswith("requirements:") or lower.startswith("build:"):
                in_dependencies = True
                in_channels = False
                in_pip_section = False
                continue

            if in_channels and not stripped.startswith("-"):
                in_channels = False

            if PIP_SECTION_PATTERN.match(stripped):
                in_pip_section = True
                continue

            if in_pip_section and stripped.startswith("- "):
                dep_match = re.match(r"^\s*-\s+([a-zA-Z0-9_.-]+)", stripped)
                if dep_match:
                    info.dependencies.append(f"pip:{dep_match.group(1)}")
            elif in_channels:
                channel_match = CHANNEL_PATTERN.match(stripped)
                if channel_match:
                    info.channels.append(channel_match.group(1))
            elif in_dependencies and stripped.startswith("- "):
                dep_match = DEPENDENCY_PATTERN.match(stripped)
                if dep_match and dep_match.group(1).lower() != "pip":
                    info.dependencies.append(dep_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Conda config — use CONDA_TOKEN or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ANACONDA_TOKEN_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="anaconda_token",
                        severity="high",
                        message="Anaconda/Conda token in config — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Conda config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for Conda channels and direct URL deps",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in VCS URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(stripped) and (
                in_dependencies or in_pip_section
            ):
                findings.append(
                    CondaFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies and commit conda-lock",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep ssl_verify enabled for remote channels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    CondaFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if path.name.lower() in CONDA_ENV_NAMES:
            parent = path.parent
            has_lock = any(
                (parent / lock_name).exists() for lock_name in CONDA_LOCK_NAMES
            )
            if not has_lock:
                findings.append(
                    CondaFinding(
                        kind="missing_lockfile",
                        severity="low",
                        message="conda-lock file missing — commit lockfile for reproducible environments",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[CondaFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CondaFinding] = []
        infos: list[CondaInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = CondaStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CondaStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CondaInfo]:
        """Return parsed config metadata."""
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

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened environment.yml snippet with secure defaults."""
        return """\
# environment.yml — hardened defaults for Conda projects
name: myenv
channels:
  - conda-forge
dependencies:
  - python=3.10
  # Pin versions explicitly, e.g. numpy=1.26.4
  # Use pip deps with exact versions under pip:
  #   - pip:
  #     - requests==2.31.0

# Generate and commit a lockfile for reproducible installs:
#   conda-lock -f environment.yml
# Store credentials via environment variables:
#   export CONDA_TOKEN=<token>
# Never commit tokens in environment.yml or meta.yaml
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Conda configs: none found"
        return (
            f"Conda configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Conda analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            channels = ", ".join(info.channels[:8]) if info.channels else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.channels)} channel(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    channels: {channels}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
