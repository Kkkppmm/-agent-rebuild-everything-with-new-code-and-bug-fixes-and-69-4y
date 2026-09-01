"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
MATURIN_CARGO_NAMES = ("Cargo.toml",)
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|"
    r"build-backend\s*=\s*[\"']maturin[\"']|MATURIN_)",
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
    r"trusted-host\s*=|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
DANGEROUS_RUSTC_ARG_PATTERN = re.compile(
    r"(?:rustc-extra-args|RUSTFLAGS)\s*=\s*.*(?:link-arg=-z\s*relro|-C\s*link-arg|"
    r"-C\s*force-frame-pointers=no|panic=abort|overflow-checks=false)",
    re.IGNORECASE,
)
PRE_BUILD_HOOK_PATTERN = re.compile(
    r"(?:pre-build|before-build|post-build|build-script)\s*=",
    re.IGNORECASE,
)
SKIP_AUDITWHEEL_PATTERN = re.compile(
    r"(?:skip-auditwheel|auditwheel\s*=\s*false)\s*=\s*true",
    re.IGNORECASE,
)
UNSAFE_BINDINGS_PATTERN = re.compile(
    r"bindings\s*=\s*[\"'](?:cffi|bin)[\"']",
    re.IGNORECASE,
)
SENSITIVE_ENV_PATTERN = re.compile(
    r"(?:MATURIN_PASSWORD|MATURIN_USERNAME|CARGO_REGISTRY_TOKEN|"
    r"RUSTUP_TOOLCHAIN|PYO3_PYTHON)\s*=\s*[\"'][^\"']+[\"']",
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
    bindings: str = ""
    features: list[str] = field(default_factory=list)
    build_hooks: list[str] = field(default_factory=list)


@dataclass
class MaturinStats:
    """Aggregate maturin analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_maturin_file(path: Path) -> bool:
    """Return True if the path looks like a maturin configuration file."""
    name = path.name
    if name in MATURIN_CARGO_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            cargo_toml = path.parent / "pyproject.toml"
            if cargo_toml.exists():
                py_head = cargo_toml.read_text(encoding="utf-8", errors="replace")[:8192]
                if MATURIN_MARKER_PATTERN.search(py_head):
                    return True
        except OSError:
            pass
    if name in MATURIN_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if MATURIN_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "Cargo.toml":
        return "cargo"
    return "unknown"


class MaturinAnalyzer:
    """Audit maturin configuration for security issues.

    Scans pyproject.toml (with [tool.maturin] or maturin build-backend),
    and associated Cargo.toml for hardcoded PyPI tokens, insecure HTTP URLs,
    credentials in git/source URLs, curl-pipe-to-shell in build hooks, unpinned
    git dependencies, dangerous rustc-extra-args, and sensitive path includes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MaturinFinding] | None = None
        self._stats: MaturinStats | None = None
        self._infos: list[MaturinInfo] | None = None

    def configs(self) -> list[Path]:
        """Return maturin configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_maturin_file(path):
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
            if not stripped or stripped.startswith("#"):
                continue

            bindings_match = re.search(r"bindings\s*=\s*[\"']([^\"']+)[\"']", stripped, re.IGNORECASE)
            if bindings_match:
                info.bindings = bindings_match.group(1)

            features_match = re.search(r"features\s*=\s*\[([^\]]+)\]", stripped, re.IGNORECASE)
            if features_match:
                info.features.extend(
                    f.strip().strip("\"'") for f in features_match.group(1).split(",") if f.strip()
                )

            hook_match = PRE_BUILD_HOOK_PATTERN.search(stripped)
            if hook_match:
                info.build_hooks.append(hook_match.group(0).rstrip("=").strip())

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
                        message="PyPI token in maturin config — use MATURIN_PASSWORD env var from CI secrets",
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

            if SENSITIVE_ENV_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="sensitive_env",
                        severity="high",
                        message="sensitive env var in maturin config — inject via CI secrets at build time",
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
                        message="insecure HTTP URL — use HTTPS for crate indexes and custom sources",
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

            if DANGEROUS_RUSTC_ARG_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="dangerous_rustc_arg",
                        severity="medium",
                        message="risky rustc-extra-args — review for security hardening side effects",
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
                        message="auditwheel skipped — ensure manylinux compliance is validated elsewhere",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNSAFE_BINDINGS_PATTERN.search(line) and info.file_kind == "pyproject":
                findings.append(
                    MaturinFinding(
                        kind="unsafe_bindings",
                        severity="low",
                        message="non-pyo3 bindings — review FFI surface for memory safety risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRE_BUILD_HOOK_PATTERN.search(line) and (
                CURL_PIPE_SHELL_PATTERN.search(line)
                or re.search(r"(?:rm\s+-rf|chmod\s+777|eval\s+\$|sudo\s+)", line, re.IGNORECASE)
            ):
                findings.append(
                    MaturinFinding(
                        kind="dangerous_build_hook",
                        severity="high",
                        message="dangerous command in maturin build hook — review for supply-chain risks",
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
        """Scaffold a hardened [tool.maturin] snippet with secure defaults."""
        return """\
# pyproject.toml — hardened maturin defaults for Rust/Python packages
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
# Use pyo3 bindings with extension-module feature for wheels
bindings = "pyo3"
features = ["pyo3/extension-module"]
# Pin git dependencies in Cargo.toml to tags or commit SHAs
# Store PyPI credentials via CI secrets:
#   export MATURIN_USERNAME=__token__
#   export MATURIN_PASSWORD=pypi-<token>
# Never commit tokens in pyproject.toml or Cargo.toml
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
            features = ", ".join(info.features[:8]) if info.features else "none"
            hooks = ", ".join(info.build_hooks[:8]) if info.build_hooks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"bindings={info.bindings or 'unset'}, {len(info.features)} feature(s)"
            )
            lines.append(f"    features: {features}")
            lines.append(f"    build hooks: {hooks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
