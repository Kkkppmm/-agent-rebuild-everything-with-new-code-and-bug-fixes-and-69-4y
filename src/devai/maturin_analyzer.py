"""MaturinAnalyzer — audit maturin pyproject.toml and Cargo.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MATURIN_PYPROJECT_NAMES = ("pyproject.toml",)
MATURIN_CARGO_NAMES = ("Cargo.toml",)
MATURIN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.maturin\]|^\[tool\.maturin\.|maturin\s*=\s*\{|"
    r"build-backend\s*=\s*[\"']maturin[\"']|maturin\.build)",
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
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.env(?:\.|$)|"
    r"\.pem|\.key|id_rsa|credentials\.json|secrets?\.ya?ml)",
    re.IGNORECASE,
)
SENSITIVE_INCLUDE_PATTERN = re.compile(
    r"(?:include|exclude|python-source|data)\s*=\s*.*"
    r"(?:\.env|\.ssh|\.aws|\.pem|\.key|id_rsa|credentials|secrets?)",
    re.IGNORECASE,
)
AUDITWHEEL_SKIP_PATTERN = re.compile(
    r"(?:auditwheel|skip-auditwheel)\s*=\s*[\"']?(?:skip|false|0)[\"']?",
    re.IGNORECASE,
)
STRIP_DISABLED_PATTERN = re.compile(
    r"strip\s*=\s*false",
    re.IGNORECASE,
)
DANGEROUS_CARGO_ARGS_PATTERN = re.compile(
    r"cargo-extra-args\s*=\s*.*(?:--features\s+.*debug|--release\s+false|"
    r"-Z\s+unstable-options|--config\s+net\.git-fetch-with-cli)",
    re.IGNORECASE,
)
INSECURE_ENV_VAR_PATTERN = re.compile(
    r"(?:MATURIN_PYPI_TOKEN|MATURIN_PASSWORD|TWINE_PASSWORD|TWINE_USERNAME|"
    r"CARGO_REGISTRY_TOKEN)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
UNSAFE_FEATURE_PATTERN = re.compile(
    r"(?:features|default-features)\s*=\s*.*(?:dangerous|unsafe|insecure)",
    re.IGNORECASE,
)
BINDGEN_PATTERN = re.compile(
    r"(?:binding|bindings)\s*=\s*[\"']PyO3[\"']",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
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
    features: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    module_name: str = ""


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
            if MATURIN_MARKER_PATTERN.search(head) or "[lib]" in head:
                parent_pyproject = path.parent / "pyproject.toml"
                if parent_pyproject.is_file():
                    py_head = parent_pyproject.read_text(encoding="utf-8", errors="replace")[:8192]
                    if MATURIN_MARKER_PATTERN.search(py_head):
                        return True
        except OSError:
            pass
        return False
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

    Scans pyproject.toml (with [tool.maturin]) and related Cargo.toml for
    hardcoded PyPI tokens, sensitive files in include/data paths, auditwheel
    skips, disabled symbol stripping, credentials in repository URLs,
    curl-pipe-to-shell in build hooks, and insecure cargo-extra-args.
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

            module_match = re.search(
                r"module-name\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if module_match:
                info.module_name = module_match.group(1)

            feature_match = re.search(
                r"features\s*=\s*\[([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if feature_match:
                info.features.extend(
                    f.strip().strip("\"'") for f in feature_match.group(1).split(",") if f.strip()
                )

            include_match = re.search(
                r"(?:include|python-source)\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if include_match:
                info.includes.append(include_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in maturin config — use MATURIN_PYPI_TOKEN or CI secret stores",
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

            if INSECURE_ENV_VAR_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="publish_credential",
                        severity="high",
                        message="publish credentials in maturin config — use env vars or keyring",
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
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and custom sources",
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

            if SENSITIVE_INCLUDE_PATTERN.search(line) or (
                SENSITIVE_PATH_PATTERN.search(line)
                and re.search(r"(?:include|exclude|python-source|data)\s*=", stripped, re.IGNORECASE)
            ):
                findings.append(
                    MaturinFinding(
                        kind="sensitive_include",
                        severity="high",
                        message="sensitive file in maturin include/data paths — exclude secrets from wheels",
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
                        message="auditwheel disabled — wheels may ship with vulnerable native libraries",
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
                        message="symbol stripping disabled — release wheels may leak debug information",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_CARGO_ARGS_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="dangerous_cargo_args",
                        severity="medium",
                        message="risky cargo-extra-args — review for debug features or insecure network settings",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNSAFE_FEATURE_PATTERN.search(line):
                findings.append(
                    MaturinFinding(
                        kind="unsafe_feature",
                        severity="medium",
                        message="feature flag with unsafe naming — review for security implications",
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

            if BINDGEN_PATTERN.search(line) and "abi3" not in stripped.lower():
                findings.append(
                    MaturinFinding(
                        kind="pyo3_binding",
                        severity="low",
                        message="PyO3 binding without abi3 — consider limited API for broader wheel compatibility",
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
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
# Pin module name; avoid including secrets in wheels
# module-name = "my_package._native"
# python-source = "python"
# strip = true
# Use MATURIN_PYPI_TOKEN for publishing — never commit tokens
# compatibility = "linux"  # or "manylinux2014" for broader support
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
            includes = ", ".join(info.includes[:8]) if info.includes else "none"
            module = info.module_name or "unset"
            lines.append(
                f"  - {info.path} ({info.file_kind}): module={module}, "
                f"{len(info.features)} feature(s), {len(info.includes)} include(s)"
            )
            lines.append(f"    features: {features}")
            lines.append(f"    includes: {includes}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
