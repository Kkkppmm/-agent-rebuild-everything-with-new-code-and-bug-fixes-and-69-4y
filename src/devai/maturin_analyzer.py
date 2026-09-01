"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
MATURIN_CARGO_NAMES = ("Cargo.toml",)
MATURIN_CARGO_CONFIG_NAMES = ("config.toml", "config")
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|build-backend\s*=\s*[\"']maturin|"
    r"requires\s*=\s*\[[^\]]*maturin|maturin\s*=\s*\{)",
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
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|/etc/passwd|/etc/shadow|\.kube/config|id_rsa)",
    re.IGNORECASE,
)
SENSITIVE_INCLUDE_PATTERN = re.compile(
    r"include\s*=\s*\[[^\]]*(?:\.env|\.pem|\.ssh|id_rsa|secrets?)",
    re.IGNORECASE,
)
AUDITWHEEL_SKIP_PATTERN = re.compile(
    r"(?:auditwheel|audit-wheel)\s*=\s*[\"']?(?:skip|none|false)[\"']?",
    re.IGNORECASE,
)
UNSAFE_RUSTFLAGS_PATTERN = re.compile(
    r"(?:RUSTFLAGS|rustflags)\s*[=:]\s*[\"'][^\"']*(?:-C\s+link-arg=-z\s+norelro|-C\s+link-arg=-Wl,-z,relro,-z,nox)",
    re.IGNORECASE,
)
BEFORE_BUILD_SCRIPT_PATTERN = re.compile(
    r"(?:before-all|before-build|after-build|post-install)\s*=\s*[\"']",
    re.IGNORECASE,
)
REGISTRY_TOKEN_PATTERN = re.compile(
    r"(?:[\"']?cargo[_-]?token[\"']?|^\s*token)\s*=\s*[\"'][^\"'\s${}]+[\"']",
    re.IGNORECASE | re.MULTILINE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:http-check-revoke\s*=\s*false|check-revoke\s*=\s*false|"
    r"insecure\s*=\s*true|verify\s*=\s*false)",
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
    dependencies: list[str] = field(default_factory=list)


@dataclass
class MaturinStats:
    """Aggregate maturin analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_maturin_pyproject(path: Path) -> bool:
    """Return True if pyproject.toml uses maturin."""
    if path.name not in MATURIN_PYPROJECT_NAMES:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(MATURIN_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _is_maturin_cargo(path: Path, maturin_roots: set[Path]) -> bool:
    """Return True if Cargo.toml belongs to a maturin project."""
    if path.name not in MATURIN_CARGO_NAMES:
        return False
    for root in maturin_roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _is_maturin_cargo_config(path: Path, maturin_roots: set[Path]) -> bool:
    """Return True if .cargo/config belongs to a maturin project."""
    if path.name not in MATURIN_CARGO_CONFIG_NAMES:
        return False
    if path.parent.name != ".cargo":
        return False
    project_root = path.parent.parent
    for root in maturin_roots:
        if project_root == root or project_root in maturin_roots:
            return True
        try:
            project_root.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "Cargo.toml":
        return "cargo_manifest"
    if name in MATURIN_CARGO_CONFIG_NAMES and path.parent.name == ".cargo":
        return "cargo_config"
    return "unknown"


def _maturin_project_roots(root: Path) -> set[Path]:
    """Find directories that contain maturin pyproject.toml files."""
    roots: set[Path] = set()
    for path in sorted(root.rglob("pyproject.toml")):
        if path.is_file() and _is_maturin_pyproject(path):
            roots.add(path.parent)
    return roots


class MaturinAnalyzer:
    """Audit maturin configuration for security issues.

    Scans pyproject.toml (with [tool.maturin] or maturin build-backend),
    associated Cargo.toml, and .cargo/config.toml for hardcoded PyPI/cargo
    tokens, insecure HTTP registry URLs, credentials in git URLs, unpinned
    git dependencies, auditwheel skips, sensitive file includes, dangerous
    before-build scripts, and unsafe RUSTFLAGS.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MaturinFinding] | None = None
        self._stats: MaturinStats | None = None
        self._infos: list[MaturinInfo] | None = None

    def configs(self) -> list[Path]:
        """Return maturin configuration paths found in the project."""
        maturin_roots = _maturin_project_roots(self.root)
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_maturin_pyproject(path):
                found.append(path)
            elif _is_maturin_cargo(path, maturin_roots):
                found.append(path)
            elif _is_maturin_cargo_config(path, maturin_roots):
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

            binding_match = re.search(
                r"(?:bindings?|module-name)\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if binding_match:
                info.bindings.append(binding_match.group(1))

            feature_match = re.search(
                r"features\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if feature_match:
                info.features.extend(
                    f.strip().strip("\"'")
                    for f in feature_match.group(1).split(",")
                    if f.strip()
                )

            dep_match = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*", stripped)
            if dep_match and not stripped.startswith("["):
                dep_name = dep_match.group(1)
                if dep_name not in ("name", "version", "description", "authors", "license"):
                    info.dependencies.append(dep_name)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in maturin config — use env vars or secret stores",
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
                        kind="cargo_token",
                        severity="high",
                        message="cargo registry token in config — use cargo login or credential helpers",
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
                        message="AWS access key in maturin config — use credential helpers or secret stores",
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
                        message="insecure HTTP URL — use HTTPS for registries and download sources",
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

            if DYNAMIC_VERSION_PATTERN.search(stripped) and (
                "dependencies" in stripped.lower() or "=" in stripped
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
                        message="sensitive path reference — avoid bundling credentials in wheels/sdists",
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
                        message="include pattern may bundle secrets — exclude .env, keys, and credential files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AUDITWHEEL_SKIP_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="auditwheel_skip",
                        severity="medium",
                        message="auditwheel disabled — wheels may ship non-compliant shared libraries",
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
                        message="unsafe RUSTFLAGS — review linker hardening and relro settings",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BEFORE_BUILD_SCRIPT_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="build_hook_script",
                        severity="medium",
                        message="maturin build hook script — review for supply-chain risks",
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
# pyproject.toml — hardened maturin defaults for Rust/Python extensions
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
# Pin features explicitly; avoid bundling secrets in include patterns
# features = ["pyo3/extension-module"]
# python-source = "python"
# module-name = "my_extension._native"

# Use CI secrets for publishing:
#   export MATURIN_PYPI_TOKEN=pypi-<token>
# Never commit tokens in pyproject.toml or Cargo.toml

# Run auditwheel on Linux wheels (do not set auditwheel = "skip")
# Exclude sensitive files from sdist/wheel bundles:
# exclude = [".env", "*.pem", ".ssh/*"]
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
            bindings = ", ".join(info.bindings[:8]) if info.bindings else "none"
            features = ", ".join(info.features[:8]) if info.features else "none"
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies)"
            )
            lines.append(f"    bindings: {bindings}")
            lines.append(f"    features: {features}")
            lines.append(f"    dependencies: {deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
