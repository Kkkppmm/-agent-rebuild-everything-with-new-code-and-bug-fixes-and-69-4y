"""MaturinAnalyzer — audit maturin pyproject.toml, maturin.toml, and Cargo.toml configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
MATURIN_CONFIG_NAMES = ("maturin.toml",)
MATURIN_CARGO_NAMES = ("Cargo.toml",)
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|"
    r"build-backend\s*=\s*[\"']maturin|requires\s*=\s*\[[^\]]*maturin|"
    r"MATURIN_)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|cargo[_-]?token|"
    r"registry[_-]?token|http-basic)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
REGISTRY_TOKEN_PATTERN = re.compile(
    r"(?:[\"']?cargo[_-]?token[\"']?|^\s*token)\s*=\s*[\"'][^\"'\s${}]+[\"']",
    re.IGNORECASE | re.MULTILINE,
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
    r"=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:branch|rev|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"git\s*=\s*[\"'][^\"']+#(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|http-check-revoke\s*=\s*false|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.env\b)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:module-name|python-source|manifest-path|path)\s*=\s*[\"']\.\./",
    re.IGNORECASE,
)
SENSITIVE_INCLUDE_PATTERN = re.compile(
    r"(?:include|exclude)\s*=\s*\[[^\]]*(?:\.env|\.ssh|\.aws|secrets?)",
    re.IGNORECASE,
)
BUILD_HOOK_PATTERN = re.compile(
    r"(?:before-build|after-build|pre-build|post-build)\s*=",
    re.IGNORECASE,
)
SKIP_AUDITWHEEL_PATTERN = re.compile(
    r"(?:skip-auditwheel|skip_auditwheel)\s*=\s*true",
    re.IGNORECASE,
)
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh|"
    r"eval\s+\$|sudo\s+)",
    re.IGNORECASE,
)
STRIP_DISABLED_PATTERN = re.compile(
    r"(?:strip\s*=\s*false|strip\s*=\s*False)",
    re.IGNORECASE,
)


@dataclass
class MaturinFinding:
    """A security or best-practice issue in a maturin configuration file."""

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
class MaturinInfo:
    """Parsed metadata about a maturin configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    bindings: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)


@dataclass
class MaturinStats:
    """Aggregate maturin analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _has_maturin_marker(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(MATURIN_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _maturin_roots(root: Path) -> set[Path]:
    """Return directories that contain maturin configuration."""
    roots: set[Path] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in MATURIN_CONFIG_NAMES:
            roots.add(path.parent)
        elif path.name in MATURIN_PYPROJECT_NAMES and _has_maturin_marker(path):
            roots.add(path.parent)
    return roots


def _is_maturin_file(path: Path, maturin_roots: set[Path]) -> bool:
    """Return True if the path looks like a maturin configuration file."""
    name = path.name
    if name in MATURIN_CONFIG_NAMES:
        return True
    if name in MATURIN_PYPROJECT_NAMES and _has_maturin_marker(path):
        return True
    if name in MATURIN_CARGO_NAMES:
        for crate_root in maturin_roots:
            try:
                path.relative_to(crate_root)
                return True
            except ValueError:
                continue
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "maturin.toml":
        return "maturin_config"
    if name == "Cargo.toml":
        return "cargo_manifest"
    return "unknown"


class MaturinAnalyzer:
    """Audit maturin configuration for security issues.

    Scans pyproject.toml (with [tool.maturin]), maturin.toml, and associated
    Cargo.toml for hardcoded PyPI/Cargo tokens, insecure HTTP URLs, credentials
    in git/source URLs, unpinned git dependencies, path traversal in module-name,
    sensitive files in include patterns, curl-pipe-to-shell in build hooks,
    disabled auditwheel stripping, and dangerous repair commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MaturinFinding] | None = None
        self._stats: MaturinStats | None = None
        self._infos: list[MaturinInfo] | None = None

    def configs(self) -> list[Path]:
        """Return maturin configuration paths found in the project."""
        maturin_roots = _maturin_roots(self.root)
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_maturin_file(path, maturin_roots):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MaturinFinding], MaturinInfo]:
        findings: list[MaturinFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MaturinInfo(path=rel)

        raw_lines = text.splitlines()
        info = MaturinInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue

            bindings_match = re.search(
                r"bindings\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if bindings_match:
                binding = bindings_match.group(1)
                if binding not in info.bindings:
                    info.bindings.append(binding)

            features_match = re.search(
                r"features\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if features_match:
                for feat in re.findall(r"[\"']([^\"']+)[\"']", features_match.group(1)):
                    if feat not in info.features:
                        info.features.append(feat)

            target_match = re.search(
                r"target\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if target_match:
                target = target_match.group(1)
                if target not in info.targets:
                    info.targets.append(target)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in maturin config — use CI secret stores or env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in maturin config — use MATURIN_PYPI_TOKEN or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if REGISTRY_TOKEN_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="registry_token",
                        severity="high",
                        message="Cargo registry token in maturin config — use CARGO_REGISTRY_TOKEN from CI",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in maturin config — use OIDC or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and crate registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                and (
                    re.search(
                        r"(?:dependencies|dev-dependencies|build-dependencies|patch)",
                        stripped,
                        re.IGNORECASE,
                    )
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    MaturinFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in maturin config — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_COMMAND_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="dangerous_command",
                        severity="high",
                        message="dangerous command in maturin build hook — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
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
                    MaturinFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in wheels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PATH_TRAVERSAL_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="path_traversal",
                        severity="high",
                        message="path traversal in module-name or python-source — keep paths within project root",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_INCLUDE_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="sensitive_include",
                        severity="high",
                        message="sensitive file pattern in include/exclude — avoid shipping secrets in wheels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BUILD_HOOK_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="build_hook",
                        severity="medium",
                        message="custom build hook in maturin config — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_AUDITWHEEL_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="skip_auditwheel",
                        severity="medium",
                        message="auditwheel skipped — ensure wheels meet manylinux compliance without repair",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if STRIP_DISABLED_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="strip_disabled",
                        severity="low",
                        message="binary stripping disabled — enable strip=true to reduce wheel size and symbol leakage",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[MaturinFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MaturinFinding] = []
        infos: list[MaturinInfo] = []
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
        self._stats = MaturinStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MaturinStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MaturinInfo]:
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
        """Scaffold a hardened pyproject.toml [tool.maturin] snippet with secure defaults."""
        return """\
# pyproject.toml — hardened [tool.maturin] defaults for Rust/Python extensions
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
# Pin module layout within project root
python-source = "python"
module-name = "my_package._native"
bindings = "pyo3"
strip = true
# Store publish tokens via CI secrets:
#   export MATURIN_PYPI_TOKEN=pypi-<token>
#   export CARGO_REGISTRY_TOKEN=<token>
# Never commit tokens in pyproject.toml, maturin.toml, or Cargo.toml
# Pin git dependencies to commit SHAs in Cargo.toml
# Run auditwheel repair in CI; avoid skip-auditwheel unless justified
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "maturin configs: none found"
        return (
            f"maturin configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "maturin analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            bindings = ", ".join(info.bindings[:8]) if info.bindings else "none"
            features = ", ".join(info.features[:8]) if info.features else "none"
            targets = ", ".join(info.targets[:8]) if info.targets else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.bindings)} binding(s), {len(info.features)} feature(s)"
            )
            lines.append(f"    bindings: {bindings}")
            lines.append(f"    features: {features}")
            lines.append(f"    targets: {targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
