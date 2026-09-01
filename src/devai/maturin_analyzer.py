"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
MATURIN_CARGO_NAMES = ("Cargo.toml",)
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|\[package\].*name)",
    re.IGNORECASE | re.MULTILINE,
)
CARGO_MATURIN_PATTERN = re.compile(
    r"(?:maturin|pyo3|cdylib|cdylib-type)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
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
DYNAMIC_VERSION_PATTERN = re.compile(
    r"version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"[a-zA-Z0-9_.-]+\s*=\s*[\"']\*[\"']",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false)",
    re.IGNORECASE,
)
ABI3_DISABLED_PATTERN = re.compile(
    r"abi3\s*=\s*false",
    re.IGNORECASE,
)
UNSAFE_BINDINGS_PATTERN = re.compile(
    r"(?:module-name|python-source)\s*=\s*[\"']\.\./",
    re.IGNORECASE,
)
CARGO_GIT_UNPINNED_PATTERN = re.compile(
    r"\[dependencies\.[^\]]+\]\s*\n(?:.*\n)*?git\s*=\s*\"[^\"]+\"(?:\n(?!rev|branch|tag))",
    re.IGNORECASE | re.MULTILINE,
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
    features: list[str] = field(default_factory=list)
    bindings: str = ""


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
    if name in MATURIN_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if re.search(r"\[tool\.maturin\]|maturin\s*=\s*\{", head, re.IGNORECASE):
                return True
        except OSError:
            pass
    if name in MATURIN_CARGO_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CARGO_MATURIN_PATTERN.search(head):
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

    Scans pyproject.toml [tool.maturin] and Cargo.toml for hardcoded PyPI tokens,
    insecure HTTP repository URLs, credentials in git/source URLs, unpinned git
    dependencies, disabled abi3, and unsafe python-source paths.
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

            feature_match = re.search(r"features\s*=\s*\[([^\]]+)\]", stripped, re.IGNORECASE)
            if feature_match:
                info.features.extend(f.strip().strip("\"'") for f in feature_match.group(1).split(","))

            bindings_match = re.search(r"bindings\s*=\s*[\"']([^\"']+)[\"']", stripped, re.IGNORECASE)
            if bindings_match:
                info.bindings = bindings_match.group(1)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in maturin config — use MATURIN_* env vars or CI secrets",
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
                        message="PyPI token in maturin config — use MATURIN_PYPI_TOKEN env var",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="insecure_http",
                        severity="high",
                        message="insecure HTTP URL in maturin config — use HTTPS",
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
                        message="credentials embedded in git/source URL — use SSH keys or token env vars",
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
                        message="unpinned git dependency (main/master/HEAD) — pin to a commit or tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="unpinned or wildcard version constraint — pin dependencies",
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
                        message="disabled SSL verification in maturin config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ABI3_DISABLED_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="abi3_disabled",
                        severity="low",
                        message="abi3 disabled — consider enabling for broader wheel compatibility",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNSAFE_BINDINGS_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="unsafe_bindings_path",
                        severity="medium",
                        message="python-source or module-name points outside project root",
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
        """Scaffold a hardened maturin config snippet with secure defaults."""
        return """\
# pyproject.toml — hardened maturin defaults
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
features = ["pyo3/extension-module"]
abi3 = true
# Use MATURIN_PYPI_TOKEN env var for publishing; never commit tokens
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Maturin configs: none found"
        return (
            f"Maturin configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Maturin analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            features = ", ".join(info.features[:8]) if info.features else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"bindings={info.bindings or 'default'}, features={features}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
