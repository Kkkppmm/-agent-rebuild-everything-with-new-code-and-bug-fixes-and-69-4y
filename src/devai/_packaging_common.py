"""Shared scanning engine for Python packaging tool analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generic, TypeVar

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
    r"=\s*\{[^}]*version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"(?:>=|<=|>|<)\s*[\"']?\d",
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
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"native-tls\s*=\s*false|allow-insecure-host|trusted-host\s*=|cert\s*=\s*/dev/null|"
    r"insecureSkipTlsVerify|trustAllCertificates)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"(?:--trusted-host|trusted-host)\s*[= ]?\s*([^\s#]+)",
    re.IGNORECASE,
)
INDEX_URL_PATTERN = re.compile(
    r"(?:index-url|extra-index-url|url|index)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)


@dataclass
class PackagingToolConfig:
    """Configuration for a Python packaging tool analyzer."""

    tool_name: str
    secret_message: str
    marker_patterns: tuple[re.Pattern[str], ...] = ()
    extra_filenames: tuple[str, ...] = ()
    pyproject_names: tuple[str, ...] = ("pyproject.toml",)
    lock_filenames: tuple[str, ...] = ()
    lock_parent_pyproject: str = "pyproject.toml"
    hardened_snippet: str = ""
    file_kind_map: dict[str, str] = field(default_factory=dict)


FindingT = TypeVar("FindingT")
InfoT = TypeVar("InfoT")
StatsT = TypeVar("StatsT")


def _default_file_kind(name: str, config: PackagingToolConfig) -> str:
    if name in config.file_kind_map:
        return config.file_kind_map[name]
    if name == "pyproject.toml":
        return "pyproject"
    if name.endswith(".lock"):
        return "lock"
    if name.endswith(".in"):
        return "requirements_in"
    return "config"


def _is_config_file(path: Path, config: PackagingToolConfig) -> bool:
    name = path.name
    if name in config.extra_filenames:
        return True
    if name in config.pyproject_names and config.marker_patterns:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            return any(p.search(head) for p in config.marker_patterns)
        except OSError:
            return False
    return False


def make_packaging_analyzer(
    prefix: str,
    config: PackagingToolConfig,
) -> tuple[type, type, type, type]:
    """Create Finding, Info, Stats, and Analyzer classes for a packaging tool."""

    @dataclass
    class Finding:
        kind: str
        severity: str
        message: str
        path: str
        lineno: int
        line: str = ""

        def format(self) -> str:
            return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"

    @dataclass
    class Info:
        path: str
        lines: int = 0
        file_kind: str = ""
        dependencies: list[str] = field(default_factory=list)
        index_urls: list[str] = field(default_factory=list)

    @dataclass
    class Stats:
        configs: int = 0
        files: int = 0
        findings: int = 0
        high_severity: int = 0
        medium_severity: int = 0
        low_severity: int = 0

    class Analyzer:
        """Audit packaging configuration for security issues."""

        def __init__(self, root: str) -> None:
            self.root = Path(root)
            self._findings: list[Finding] | None = None
            self._stats: Stats | None = None
            self._infos: list[Info] | None = None

        def configs(self) -> list[Path]:
            found: list[Path] = []
            for path in sorted(self.root.rglob("*")):
                if path.is_file() and _is_config_file(path, config):
                    found.append(path)
            return found

        def _analyze_file(self, path: Path) -> tuple[list[Finding], Info]:
            findings: list[Finding] = []
            rel = str(path.relative_to(self.root))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return findings, Info(path=rel)

            raw_lines = text.splitlines()
            info = Info(
                path=rel,
                lines=len(raw_lines),
                file_kind=_default_file_kind(path.name, config),
            )

            for lineno, line in enumerate(raw_lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                index_match = INDEX_URL_PATTERN.search(stripped)
                if index_match:
                    info.index_urls.append(index_match.group(1))

                dep_match = re.search(
                    r"^([a-zA-Z0-9_.-]+)\s*=\s*(?:\{|[\"'])",
                    stripped,
                )
                if dep_match and not stripped.startswith("["):
                    dep_name = dep_match.group(1)
                    if dep_name not in ("name", "version", "description", "authors", "license"):
                        info.dependencies.append(dep_name)

                checks: list[tuple[re.Pattern[str], str, str, str]] = [
                    (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", config.secret_message),
                    (PYPI_TOKEN_PATTERN, "pypi_token", "high", f"PyPI token in {config.tool_name} config — use env vars or keyring"),
                    (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key — use credential helpers or secret stores"),
                    (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL — use HTTPS for package indexes"),
                    (SCM_CREDENTIALS_PATTERN, "scm_credentials", "high", "credentials in repository URL — use token env vars or SSH keys"),
                    (INSECURE_SSL_PATTERN, "insecure_ssl", "high", "SSL/TLS verification disabled — keep certificate validation enabled"),
                    (TRUSTED_HOST_PATTERN, "trusted_host", "medium", "trusted-host bypass — avoid disabling TLS hostname verification"),
                    (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high", "curl/wget piped to shell — vendor scripts with checksum verification"),
                    (SENSITIVE_PATH_PATTERN, "sensitive_path", "high", "sensitive host path reference — avoid bundling credentials in builds"),
                    (GIT_DEP_UNPINNED_PATTERN, "unpinned_git_dep", "medium", "git dependency on moving branch — pin to tag or commit SHA"),
                ]

                for pattern, kind, severity, message in checks:
                    if pattern.search(line):
                        findings.append(
                            Finding(kind=kind, severity=severity, message=message, path=rel, lineno=lineno, line=line)
                        )

                if (
                    DYNAMIC_VERSION_PATTERN.search(stripped)
                    and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                    and ("=" in stripped and not stripped.startswith("["))
                ):
                    findings.append(
                        Finding(
                            kind="dynamic_version",
                            severity="medium",
                            message="loose version constraint — pin dependencies and commit lockfiles",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if config.lock_filenames and path.name == config.lock_parent_pyproject:
                for lock_name in config.lock_filenames:
                    lock_path = path.parent / lock_name
                    if not lock_path.exists():
                        findings.append(
                            Finding(
                                kind="missing_lockfile",
                                severity="low",
                                message=f"{lock_name} missing — commit lockfile for reproducible installs",
                                path=rel,
                                lineno=1,
                                line="",
                            )
                        )

            return findings, info

        def analyze(self) -> list[Finding]:
            if self._findings is not None:
                return self._findings

            findings: list[Finding] = []
            infos: list[Info] = []
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
            self._stats = Stats(
                configs=len(paths),
                files=len(paths),
                findings=len(findings),
                high_severity=high,
                medium_severity=medium,
                low_severity=low,
            )
            return findings

        @property
        def stats(self) -> Stats:
            if self._stats is None:
                self.analyze()
            return self._stats  # type: ignore[return-value]

        @property
        def infos(self) -> list[Info]:
            if self._infos is None:
                self.analyze()
            return self._infos  # type: ignore[return-value]

        def health_score(self) -> float:
            self.analyze()
            stats = self.stats
            if stats.configs == 0 or stats.findings == 0:
                return 100.0
            penalty = (
                stats.high_severity * 20.0
                + stats.medium_severity * 8.0
                + stats.low_severity * 2.0
            )
            return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

        def generate_hardened_config(self) -> str:
            return config.hardened_snippet or f"# Hardened {config.tool_name} config — use HTTPS and env-based secrets\n"

        def summary(self) -> str:
            self.analyze()
            stats = self.stats
            if stats.configs == 0:
                return f"{prefix} configs: none found"
            return (
                f"{prefix} configs: {stats.configs} config(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
            )

        def to_context(self) -> str:
            self.analyze()
            stats = self.stats
            lines = [
                f"{prefix} analysis:",
                f"  configs: {stats.configs}",
                f"  findings: {stats.findings}",
                f"  health score: {self.health_score()}/100",
            ]
            for info in self.infos:
                deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
                indexes = ", ".join(info.index_urls[:8]) if info.index_urls else "none"
                lines.append(
                    f"  - {info.path} ({info.file_kind}): "
                    f"{len(info.dependencies)} dependency(ies), {len(info.index_urls)} index URL(s)"
                )
                lines.append(f"    dependencies: {deps}")
                lines.append(f"    index URLs: {indexes}")
            for finding in (self._findings or [])[:25]:
                lines.append(f"  {finding.format()}")
            if self._findings and len(self._findings) > 25:
                lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
            return "\n".join(lines)

    Finding.__name__ = f"{prefix}Finding"
    Info.__name__ = f"{prefix}Info"
    Stats.__name__ = f"{prefix}Stats"
    Analyzer.__name__ = f"{prefix}Analyzer"
    Analyzer.__doc__ = f"Audit {config.tool_name} configuration for security issues."

    return Finding, Info, Stats, Analyzer
