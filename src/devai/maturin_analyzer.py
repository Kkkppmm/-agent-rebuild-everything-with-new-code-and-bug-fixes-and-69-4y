"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
CARGO_TOML_NAMES = ("Cargo.toml",)
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|"
    r"build-backend\s*=\s*[\"']maturin)",
    re.IGNORECASE | re.MULTILINE,
)
CARGO_MARKER_PATTERN = re.compile(
    r"(?:^\[package\]|^\[dependencies\]|^\[dev-dependencies\]|^\[build-dependencies\])",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
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
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
WILDCARD_FEATURES_PATTERN = re.compile(
    r"features\s*=\s*\[[^\]]*(?:\"all\"|\*)[^\]]*\]",
    re.IGNORECASE,
)
UNSAFE_BINDGEN_PATTERN = re.compile(
    r"(?:OPENSSL_DIR|OPENSSL_LIB_DIR|OPENSSL_INCLUDE_DIR)\s*=\s*[\"']/[^\"']+[\"']",
    re.IGNORECASE,
)
CARGO_GIT_DEP_PATTERN = re.compile(
    r"^\s*([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*git\s*=",
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
    dependencies: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)


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
    if name in CARGO_TOML_NAMES:
        return True
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

    Scans pyproject.toml (with [tool.maturin]) and Cargo.toml for hardcoded
    PyPI tokens, credentials in git dependency URLs, unpinned git branches,
    wildcard feature flags, curl-pipe-to-shell in build hooks, and insecure
    HTTP registry URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MaturinFinding] | None = None
        self._stats: MaturinStats | None = None
        self._infos: list[MaturinInfo] | None = None

    def configs(self) -> list[Path]:
        """Return maturin configuration paths found in the project."""
        found: list[Path] = []
        has_maturin_pyproject = False
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if path.name in MATURIN_PYPROJECT_NAMES:
                try:
                    head = path.read_text(encoding="utf-8", errors="replace")[:8192]
                    if MATURIN_MARKER_PATTERN.search(head):
                        has_maturin_pyproject = True
                        found.append(path)
                except OSError:
                    pass
            elif path.name in CARGO_TOML_NAMES and CARGO_MARKER_PATTERN.search(
                path.read_text(encoding="utf-8", errors="replace")[:8192]
            ):
                found.append(path)
        if has_maturin_pyproject:
            for path in sorted(self.root.rglob("Cargo.toml")):
                if path.is_file() and path not in found:
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

            git_dep = CARGO_GIT_DEP_PATTERN.match(stripped)
            if git_dep:
                info.dependencies.append(git_dep.group(1))

            feature_match = re.search(r"features\s*=\s*\[([^\]]+)\]", stripped, re.IGNORECASE)
            if feature_match:
                info.features.extend(f.strip().strip("\"'") for f in feature_match.group(1).split(","))

            checks: list[tuple[str, str, str, re.Pattern[str]]] = [
                ("hardcoded_secret", "high", "hardcoded secret in maturin config — use env vars or keyring", HARDCODED_SECRET_PATTERN),
                ("pypi_token", "high", "PyPI token in maturin config — use MATURIN_PYPI_TOKEN env var", PYPI_TOKEN_PATTERN),
                ("aws_access_key", "high", "AWS access key in maturin config — use credential helpers", AWS_ACCESS_KEY_PATTERN),
                ("scm_credentials", "high", "credentials embedded in git URL — use SSH or token env vars", SCM_CREDENTIALS_PATTERN),
                ("unpinned_git_dep", "medium", "git dependency pinned to moving branch — pin to tag or commit SHA", GIT_DEP_UNPINNED_PATTERN),
                ("curl_pipe_shell", "high", "curl/wget piped to shell in maturin build — vendor scripts with checksums", CURL_PIPE_SHELL_PATTERN),
                ("sensitive_path", "high", "sensitive host path reference in maturin config", SENSITIVE_PATH_PATTERN),
                ("insecure_http", "medium", "insecure HTTP URL — use HTTPS for registries and downloads", INSECURE_HTTP_PATTERN),
                ("wildcard_features", "medium", "wildcard or 'all' features enabled — pin feature sets for reproducible builds", WILDCARD_FEATURES_PATTERN),
                ("unsafe_bindgen", "medium", "hardcoded OpenSSL paths in bindgen config — use pkg-config or vendored libs", UNSAFE_BINDGEN_PATTERN),
            ]
            for kind, severity, message, pattern in checks:
                if pattern.search(line):
                    findings.append(
                        MaturinFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
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
# pyproject.toml — hardened maturin defaults
[build-system]
requires = ["maturin>=1.0,<2"]
build-backend = "maturin"

[tool.maturin]
# Pin features explicitly; avoid features = ["all"]
# features = ["pyo3/extension-module"]
# Use MATURIN_PYPI_TOKEN env var for publishing — never commit tokens
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
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): git deps={deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
