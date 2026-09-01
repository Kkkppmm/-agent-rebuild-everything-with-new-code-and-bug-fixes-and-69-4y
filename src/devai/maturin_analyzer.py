"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
CARGO_NAMES = ("Cargo.toml",)
CARGO_CONFIG_NAMES = (".cargo/config.toml", ".cargo/config")
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|"
    r"build-backend\s*=\s*[\"']maturin[\"']|requires\s*=\s*\[[^\]]*maturin)",
    re.IGNORECASE | re.MULTILINE,
)
CARGO_PYO3_PATTERN = re.compile(
    r"crate-type\s*=\s*\[[^\]]*cdylib|pyo3\s*=|maturin",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|registry[_-]?token)\s*[=:]\s*"
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
DYNAMIC_VERSION_PATTERN = re.compile(
    r"=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"=\s*\{[^}]*version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"(?:>=|<=|>|<)\s*[\"']?\d|"
    r"[a-zA-Z0-9_.-]+\s*=\s*\*",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag|ref)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|allow-insecure-host|check-revoke\s*=\s*false)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
REGISTRY_URL_PATTERN = re.compile(
    r"(?:registry|index|url|replace-with)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
UNSAFE_RUSTFLAGS_PATTERN = re.compile(
    r"(?:RUSTFLAGS|rustflags)\s*=\s*[\"'][^\"']*(?:link-arg=-z\s*noseparate|"
    r"-C\s+link-arg=-z|overflow-checks=off)[^\"']*[\"']",
    re.IGNORECASE,
)
PATCH_CRATES_IO_PATTERN = re.compile(
    r"\[patch\.[^\]]+\]",
    re.IGNORECASE,
)
CARGO_TOKEN_PATTERN = re.compile(
    r"(?:token|credential-helper)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
INSECURE_BINDGEN_PATTERN = re.compile(
    r"(?:bindgen|cc)\s*=\s*\{[^}]*features\s*=\s*\[[^\]]*runtime[^]]*\]",
    re.IGNORECASE,
)


@dataclass
class MaturinFinding:
    """A security or best-practice issue in a Maturin/Rust-Python configuration file."""

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
    """Parsed metadata about a Maturin configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    registry_urls: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)


@dataclass
class MaturinStats:
    """Aggregate Maturin analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _has_maturin_project(root: Path) -> bool:
    """Return True if the root contains a maturin pyproject.toml."""
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        head = pyproject.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(MATURIN_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _is_maturin_pyproject(path: Path) -> bool:
    if path.name not in MATURIN_PYPROJECT_NAMES:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(MATURIN_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _is_cargo_file(path: Path, root: Path) -> bool:
    if path.name not in CARGO_NAMES:
        return False
    if _has_maturin_project(root):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(CARGO_PYO3_PATTERN.search(head))
    except OSError:
        return False


def _is_cargo_config(path: Path, root: Path) -> bool:
    rel = str(path.relative_to(root)).replace("\\", "/")
    if rel not in CARGO_CONFIG_NAMES:
        return False
    return _has_maturin_project(root) or (root / "Cargo.toml").is_file()


def _is_maturin_file(path: Path, root: Path) -> bool:
    if _is_maturin_pyproject(path):
        return True
    if _is_cargo_file(path, root):
        return True
    if _is_cargo_config(path, root):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    rel_parts = path.parts
    if name == "pyproject.toml":
        return "pyproject"
    if name == "Cargo.toml":
        return "cargo"
    if name in ("config.toml", "config"):
        return "cargo_config"
    return "unknown"


class MaturinAnalyzer:
    """Audit Maturin configuration for security issues.

    Scans pyproject.toml (with maturin build backend), Cargo.toml, and
    .cargo/config.toml for hardcoded PyPI/cargo registry tokens, insecure
    HTTP registry URLs, credentials in git/source URLs, unpinned git
    dependencies, dynamic version constraints, missing Cargo.lock,
    curl-pipe-to-shell in scripts, disabled SSL verification, and
    unsafe Rust build flags.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MaturinFinding] | None = None
        self._stats: MaturinStats | None = None
        self._infos: list[MaturinInfo] | None = None
        self._is_maturin_project = _has_maturin_project(self.root)

    def configs(self) -> list[Path]:
        """Return Maturin configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_maturin_file(path, self.root):
                found.append(path)
        return found

    def _check_missing_cargo_lock(self, findings: list[MaturinFinding]) -> None:
        if not self._is_maturin_project:
            return
        cargo_lock = self.root / "Cargo.lock"
        cargo_toml = self.root / "Cargo.toml"
        if cargo_toml.is_file() and not cargo_lock.is_file():
            findings.append(
                MaturinFinding(
                    kind="missing_cargo_lock",
                    severity="medium",
                    message="Cargo.lock missing — commit lockfile for reproducible Rust builds",
                    path="Cargo.lock",
                    lineno=0,
                )
            )

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

            feature_match = re.search(
                r"features\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if feature_match:
                for feat in feature_match.group(1).split(","):
                    feat = feat.strip().strip("\"'")
                    if feat:
                        info.features.append(feat)

            dep_match = re.match(
                r"^([a-zA-Z0-9_.-]+)\s*=\s*(?:\{|[\"'])",
                stripped,
            )
            if dep_match and not stripped.startswith("["):
                dep_name = dep_match.group(1)
                if dep_name not in (
                    "name",
                    "version",
                    "description",
                    "authors",
                    "license",
                    "module-name",
                    "python-source",
                ):
                    info.dependencies.append(dep_name)

            registry_match = REGISTRY_URL_PATTERN.search(stripped)
            if registry_match:
                info.registry_urls.append(registry_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Maturin/Cargo config — use env vars or secret stores",
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
                        message="PyPI token in config — use MATURIN_PYPI_TOKEN or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CARGO_TOKEN_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="cargo_registry_token",
                        severity="high",
                        message="Cargo registry token in config — use cargo login or credential helpers",
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
                        message="AWS access key in config — use credential helpers or secret stores",
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
                        r"(?:dependencies|dev-dependencies|build-dependencies)",
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
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
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
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNSAFE_RUSTFLAGS_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="unsafe_rustflags",
                        severity="medium",
                        message="unsafe RUSTFLAGS — review linker/security hardening flags",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PATCH_CRATES_IO_PATTERN.search(stripped):
                findings.append(
                    MaturinFinding(
                        kind="patch_crates_io",
                        severity="medium",
                        message="[patch] section overrides crates.io — verify patched sources are trusted",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_BINDGEN_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="insecure_bindgen",
                        severity="low",
                        message="bindgen runtime feature enabled — prefer build-time generation",
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

        self._check_missing_cargo_lock(findings)

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
            configs=len(paths) + (1 if any(f.kind == "missing_cargo_lock" for f in findings) else 0),
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
        """Scaffold a hardened pyproject.toml snippet with secure Maturin defaults."""
        return """\
# pyproject.toml — hardened Maturin defaults for Rust-Python extensions
[build-system]
requires = ["maturin>=1.0,<2"]
build-backend = "maturin"

[project]
name = "my-extension"
version = "0.1.0"
requires-python = ">=3.10"

[tool.maturin]
# Pin features explicitly; avoid runtime bindgen in production
features = ["pyo3/extension-module"]
# Store publish tokens via MATURIN_PYPI_TOKEN — never commit tokens
# Commit Cargo.lock for reproducible release builds
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
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            registries = ", ".join(info.registry_urls[:8]) if info.registry_urls else "none"
            features = ", ".join(info.features[:8]) if info.features else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.features)} feature(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    registry URLs: {registries}")
            lines.append(f"    features: {features}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
