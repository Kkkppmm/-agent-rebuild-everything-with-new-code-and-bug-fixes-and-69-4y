"""CargoAnalyzer — audit Cargo.toml, Cargo.lock, and .cargo config for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CARGO_MANIFEST_NAMES = ("Cargo.toml",)
CARGO_CONFIG_NAMES = ("config.toml", "config")
CARGO_CONFIG_DIRS = (".cargo",)
CARGO_LOCK_NAMES = ("Cargo.lock",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
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
    r"(?:http-check-revoke\s*=\s*false|check-revoke\s*=\s*false|"
    r"ssl-version\s*=\s*[\"']?TLSv1[\"']?|"
    r"insecure\s*=\s*true|verify\s*=\s*false)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
GIT_FETCH_CLI_PATTERN = re.compile(
    r"(?:git-fetch-with-cli|git_fetch_with_cli)\s*=\s*true",
    re.IGNORECASE,
)
REGISTRY_URL_PATTERN = re.compile(
    r"(?:index|registry|url)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
BUILD_SCRIPT_PATTERN = re.compile(
    r"^\s*build\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
DEP_SECTION_PATTERN = re.compile(
    r"^\[(?:dev-)?dependencies(?:\.[^\]]+)?\]|"
    r"^\[build-dependencies\]|"
    r"^\[patch\.[^\]]+\]",
    re.IGNORECASE,
)
PACKAGE_SECTION_PATTERN = re.compile(r"^\[package\]", re.IGNORECASE)


@dataclass
class CargoFinding:
    """A security or best-practice issue in a Cargo configuration file."""

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
class CargoInfo:
    """Parsed metadata about a Cargo configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)
    is_binary: bool = False


@dataclass
class CargoStats:
    """Aggregate Cargo analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cargo_file(path: Path) -> bool:
    """Return True if the path looks like a Cargo configuration file."""
    name = path.name
    if name in CARGO_MANIFEST_NAMES or name in CARGO_LOCK_NAMES:
        return True
    if name in CARGO_CONFIG_NAMES and path.parent.name in CARGO_CONFIG_DIRS:
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "Cargo.toml":
        return "manifest"
    if name == "Cargo.lock":
        return "lock"
    if name in CARGO_CONFIG_NAMES:
        return "cargo_config"
    return "unknown"


def _has_lockfile(directory: Path) -> bool:
    return (directory / "Cargo.lock").exists()


class CargoAnalyzer:
    """Audit Cargo configuration for security issues.

    Scans Cargo.toml, .cargo/config.toml, and related files for hardcoded
    registry tokens, insecure HTTP index URLs, credentials in git/source URLs,
    unpinned git dependencies, loose version constraints, git-fetch-with-cli
    risks, disabled TLS revocation checks, and missing lockfiles for binaries.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CargoFinding] | None = None
        self._stats: CargoStats | None = None
        self._infos: list[CargoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Cargo configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cargo_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CargoFinding],
        info: CargoInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        registry_match = REGISTRY_URL_PATTERN.search(stripped)
        if registry_match and (
            "index" in stripped.lower()
            or "registry" in stripped.lower()
            or "url" in stripped.lower()
        ):
            info.registries.append(registry_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Cargo config — use CARGO_REGISTRY_TOKEN or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REGISTRY_TOKEN_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="registry_token",
                    severity="high",
                    message="registry token in config — use CARGO_REGISTRY_TOKEN env var or credentials.toml",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Cargo config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP registry/index URL — use HTTPS for crate registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DYNAMIC_VERSION_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="dynamic_version",
                    severity="medium",
                    message="loose version constraint — pin dependencies and commit Cargo.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency pinned to moving ref — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_SSL_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="insecure_ssl",
                    severity="high",
                    message="TLS verification or revocation check disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Cargo config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_FETCH_CLI_PATTERN.search(line):
            findings.append(
                CargoFinding(
                    kind="git_fetch_cli",
                    severity="medium",
                    message="git-fetch-with-cli enabled — may leak credentials via system git; prefer built-in fetch",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_cargo_toml(self, path: Path, rel: str) -> tuple[list[CargoFinding], CargoInfo]:
        findings: list[CargoFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CargoInfo(path=rel, file_kind="manifest")

        raw_lines = text.splitlines()
        info = CargoInfo(path=rel, lines=len(raw_lines), file_kind="manifest")
        in_dep_section = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if DEP_SECTION_PATTERN.match(stripped):
                in_dep_section = True
            elif stripped.startswith("[") and not DEP_SECTION_PATTERN.match(stripped):
                in_dep_section = False

            if PACKAGE_SECTION_PATTERN.match(stripped):
                in_dep_section = False

            if stripped.startswith("[[bin]]") or re.search(
                r"^\s*(?:default\s*=\s*true|path\s*=\s*[\"']src/main)",
                stripped,
                re.IGNORECASE,
            ):
                info.is_binary = True

            dep_match = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*", stripped)
            if in_dep_section and dep_match:
                dep_name = dep_match.group(1)
                if dep_name not in ("package", "version", "features", "optional", "default"):
                    info.dependencies.append(dep_name)

            self._scan_line(line, lineno, rel, findings, info)

        if info.is_binary and not _has_lockfile(path.parent):
            findings.append(
                CargoFinding(
                    kind="missing_lockfile",
                    severity="low",
                    message="Cargo.lock missing for binary crate — commit lockfile for reproducible builds",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[CargoFinding], CargoInfo]:
        findings: list[CargoFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CargoInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = CargoInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[CargoFinding], CargoInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "Cargo.toml":
            return self._analyze_cargo_toml(path, rel)
        return self._analyze_text_file(path, rel)

    def analyze(self) -> list[CargoFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CargoFinding] = []
        infos: list[CargoInfo] = []
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
        self._stats = CargoStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CargoStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CargoInfo]:
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
        """Scaffold a hardened .cargo/config.toml snippet with secure defaults."""
        return """\
# .cargo/config.toml — hardened defaults for Rust projects
# Store registry tokens via environment variables:
#   export CARGO_REGISTRY_TOKEN=your-token
[registries]
# private = { index = "https://crates.example.com/" }

[net]
git-fetch-with-cli = false
retry = 2

# [http]
# check-revoke = true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Cargo configs: none found"
        return (
            f"Cargo configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Cargo analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            registries = ", ".join(info.registries[:8]) if info.registries else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), binary={info.is_binary}"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    registries: {registries}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
