"""CibuildwheelAnalyzer — audit cibuildwheel pyproject.toml and cibuildwheel.toml configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBUILDWHEEL_PYPROJECT_NAMES = ("pyproject.toml",)
CIBUILDWHEEL_CONFIG_NAMES = ("cibuildwheel.toml", "setup.cfg")
CIBUILDWHEEL_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|^\[cibuildwheel\]|"
    r"^\[cibuildwheel\.|cibuildwheel\s*=\s*\{|CIBW_)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|http-basic)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|PIP_TRUSTED_HOST|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
SENSITIVE_ENV_PASS_PATTERN = re.compile(
    r"(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GITLAB_TOKEN|"
    r"PYPI_PASSWORD|TWINE_PASSWORD|NPM_TOKEN|DOCKER_PASSWORD|"
    r"CI_JOB_TOKEN|CARGO_REGISTRY_TOKEN)",
    re.IGNORECASE,
)
UNPINNED_DEP_VERSIONS_PATTERN = re.compile(
    r"dependency-versions\s*=\s*[\"'](?:\*|latest|LATEST)[\"']",
    re.IGNORECASE,
)
UNPINNED_PIP_INSTALL_PATTERN = re.compile(
    r"pip\s+install\s+(?:--upgrade\s+)?[a-zA-Z0-9_.-]+",
    re.IGNORECASE,
)
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh|"
    r"eval\s+\$|sudo\s+)",
    re.IGNORECASE,
)
UNTRUSTED_IMAGE_PATTERN = re.compile(
    r"(?:manylinux-image|musllinux-image|image)\s*=\s*[\"']?(?!quay\.io/pypa/)[^\"'\s#]+",
    re.IGNORECASE,
)
BUILD_HOOK_PATTERN = re.compile(
    r"(before-all|before-build|before-test|test-command|repair-wheel-command)\s*=",
    re.IGNORECASE,
)


@dataclass
class CibuildwheelFinding:
    """A security or best-practice issue in a cibuildwheel configuration file."""

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
class CibuildwheelInfo:
    """Parsed metadata about a cibuildwheel configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    build_hooks: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    environment_pass: list[str] = field(default_factory=list)


@dataclass
class CibuildwheelStats:
    """Aggregate cibuildwheel analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cibuildwheel_file(path: Path) -> bool:
    """Return True if the path looks like a cibuildwheel configuration file."""
    name = path.name
    if name in CIBUILDWHEEL_CONFIG_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CIBUILDWHEEL_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    if name in CIBUILDWHEEL_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CIBUILDWHEEL_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "cibuildwheel.toml":
        return "cibuildwheel_config"
    if name == "setup.cfg":
        return "setup_cfg"
    return "unknown"


class CibuildwheelAnalyzer:
    """Audit cibuildwheel configuration for security issues.

    Scans pyproject.toml (with [tool.cibuildwheel]), cibuildwheel.toml, and
    setup.cfg for hardcoded PyPI tokens, insecure HTTP URLs, credentials in
    git/source URLs, curl-pipe-to-shell in build hooks, unpinned dependency
    versions, sensitive environment-pass variables, and untrusted build images.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CibuildwheelFinding] | None = None
        self._stats: CibuildwheelStats | None = None
        self._infos: list[CibuildwheelInfo] | None = None

    def configs(self) -> list[Path]:
        """Return cibuildwheel configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cibuildwheel_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CibuildwheelFinding], CibuildwheelInfo]:
        findings: list[CibuildwheelFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CibuildwheelInfo(path=rel)

        raw_lines = text.splitlines()
        info = CibuildwheelInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue

            hook_match = BUILD_HOOK_PATTERN.search(stripped)
            if hook_match:
                hook_name = hook_match.group(1).lower()
                if hook_name not in info.build_hooks:
                    info.build_hooks.append(hook_name)

            platform_match = re.match(
                r"^\[tool\.cibuildwheel\.([^\]]+)\]|^\[cibuildwheel\.([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if platform_match:
                platform = platform_match.group(1) or platform_match.group(2)
                if platform and platform not in info.platforms:
                    info.platforms.append(platform)

            env_pass_match = re.search(
                r"environment-pass\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if env_pass_match:
                for var in re.findall(r"[\"']([^\"']+)[\"']", env_pass_match.group(1)):
                    info.environment_pass.append(var)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in cibuildwheel config — use CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in cibuildwheel config — use CIBW_* env vars from CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in cibuildwheel config — use OIDC or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for wheel downloads and test dependencies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in build hook — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_COMMAND_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="dangerous_command",
                        severity="high",
                        message="dangerous command in build hook — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid mounting credentials into build containers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_DEP_VERSIONS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="unpinned_dependency_versions",
                        severity="medium",
                        message="unpinned dependency-versions — pin pip/setuptools/wheel for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_PIP_INSTALL_PATTERN.search(line) and "==" not in line:
                findings.append(
                    CibuildwheelFinding(
                        kind="unpinned_pip_install",
                        severity="medium",
                        message="unpinned pip install in build hook — pin package versions for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_ENV_PASS_PATTERN.search(line) and re.search(
                r"environment-pass", stripped, re.IGNORECASE
            ):
                findings.append(
                    CibuildwheelFinding(
                        kind="sensitive_env_pass",
                        severity="medium",
                        message="sensitive variable in environment-pass — pass only required build vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNTRUSTED_IMAGE_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="untrusted_image",
                        severity="medium",
                        message="non-standard build image — prefer official quay.io/pypa images",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[CibuildwheelFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CibuildwheelFinding] = []
        infos: list[CibuildwheelInfo] = []
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
        self._stats = CibuildwheelStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CibuildwheelStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CibuildwheelInfo]:
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
        """Scaffold a hardened cibuildwheel.toml snippet with secure defaults."""
        return """\
# cibuildwheel.toml — hardened defaults for wheel builds
[tool.cibuildwheel]
# Pin build tooling for reproducible wheels
dependency-versions = ["pip==24.0", "setuptools==69.0.0", "wheel==0.42.0"]
# Use official PyPA images only
manylinux-image = "quay.io/pypa/manylinux2014_x86_64"
musllinux-image = "quay.io/pypa/musllinux_x86_64"
# Pass only required env vars from CI; never commit secrets here
# environment-pass = ["CIBW_BUILD_VERBOSITY"]
# Store PyPI tokens via CI secrets:
#   CIBW_ENVIRONMENT = "TWINE_PASSWORD={TWINE_PASSWORD}"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "cibuildwheel configs: none found"
        return (
            f"cibuildwheel configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "cibuildwheel analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            hooks = ", ".join(info.build_hooks[:8]) if info.build_hooks else "none"
            platforms = ", ".join(info.platforms[:8]) if info.platforms else "none"
            env_pass = ", ".join(info.environment_pass[:8]) if info.environment_pass else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.build_hooks)} hook(s), {len(info.platforms)} platform(s)"
            )
            lines.append(f"    build hooks: {hooks}")
            lines.append(f"    platforms: {platforms}")
            lines.append(f"    environment-pass: {env_pass}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
