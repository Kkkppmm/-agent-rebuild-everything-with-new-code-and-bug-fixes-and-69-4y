"""RuboCopAnalyzer — audit RuboCop configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".rubocop.yml",
    ".rubocop.yaml",
    ".rubocop_todo.yml",
    "rubocop.yml",
    "rubocop.yaml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DISABLED_BY_DEFAULT_PATTERN = re.compile(
    r"^\s*DisabledByDefault\s*:\s*true\s*$",
    re.IGNORECASE,
)
NEW_COPS_DISABLE_PATTERN = re.compile(
    r"^\s*NewCops\s*:\s*disable\s*$",
    re.IGNORECASE,
)
ENABLED_FALSE_PATTERN = re.compile(
    r"^\s*Enabled\s*:\s*false\s*$",
    re.IGNORECASE,
)
SECURITY_COP_HEADER_PATTERN = re.compile(
    r"^\s*Security/[A-Za-z0-9]+(?:/[A-Za-z0-9]+)?\s*:",
    re.IGNORECASE,
)
SECURITY_COP_INLINE_PATTERN = re.compile(
    r"^\s*-\s*Security/[A-Za-z0-9]+(?:/[A-Za-z0-9]+)?\s*$",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?(?:lib|app|src|config)/\*\*?/?\*?[\"']?\s*$",
    re.IGNORECASE,
)
EXCLUDE_BROAD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*\*/?\*[\"']?\s*$",
    re.IGNORECASE,
)
INHERIT_REMOTE_PATTERN = re.compile(
    r"^\s*-\s*(?:https?://|git@|git\+https?://)",
    re.IGNORECASE,
)
INHERIT_HTTP_PATTERN = re.compile(
    r"^\s*-\s*http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
REQUIRE_GEM_PATTERN = re.compile(
    r"^\s*-\s*[\"']?[\w./-]+[\"']?\s*$",
    re.IGNORECASE,
)
TARGET_RUBY_OLD_PATTERN = re.compile(
    r"^\s*TargetRubyVersion\s*:\s*(?:2\.[0-5]|1\.\d+)\s*$",
    re.IGNORECASE,
)
RUN_ALL_COPS_DISABLED_PATTERN = re.compile(
    r"^\s*RunRailsCops\s*:\s*false\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
BUNDLER_INSECURE_DISABLED_PATTERN = re.compile(
    r"^\s*Bundler/(?:InsecureRubyProtocol|InsecureRubyPlatform)\s*:",
    re.IGNORECASE,
)
RAILS_SECURITY_DISABLED_PATTERN = re.compile(
    r"^\s*Rails/(?:ContentSecurityPolicy|ForceSSL|DefaultScope)\s*:",
    re.IGNORECASE,
)


@dataclass
class RuboCopFinding:
    """A security or best-practice issue in a RuboCop configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class RuboCopInfo:
    """Parsed metadata about a RuboCop configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    disabled_cops: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    inherit_from: list[str] = field(default_factory=list)


@dataclass
class RuboCopStats:
    """Aggregate RuboCop analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".yml", ".yaml"):
        return "yaml"
    return "unknown"


class RuboCopAnalyzer:
    """Audit RuboCop configuration for lint hygiene and security risks.

    Scans .rubocop.yml, .rubocop.yaml, and .rubocop_todo.yml for disabled
    Security/* cops, broad Exclude patterns, remote inherit_from URLs,
    DisabledByDefault, NewCops: disable, hardcoded secrets, and outdated
    TargetRubyVersion settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[RuboCopFinding] | None = None
        self._stats: RuboCopStats | None = None
        self._infos: list[RuboCopInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return RuboCop configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[RuboCopFinding], RuboCopInfo]:
        findings: list[RuboCopFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, RuboCopInfo(path=rel, file_kind=_file_kind(path))

        info = RuboCopInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        section = ""
        in_all_cops = False
        in_exclude = False
        in_inherit = False
        in_require = False
        current_cop = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.endswith(":") and not stripped.startswith("-"):
                key = stripped.rstrip(":").strip()
                section = key.lower()
                in_all_cops = section == "allcops"
                in_exclude = section == "exclude"
                in_inherit = section == "inherit_from"
                in_require = section == "require"
                current_cop = key if "/" in key else ""
                self._scan_line(
                    line,
                    lineno,
                    rel,
                    findings,
                    info,
                    section,
                    in_all_cops,
                    in_exclude,
                    in_inherit,
                    in_require,
                    current_cop,
                )
                continue

            if in_exclude and stripped.startswith("-"):
                item = stripped.lstrip("-").strip().strip("'\"")
                if item and item not in info.excluded_paths:
                    info.excluded_paths.append(item)

            if in_inherit and stripped.startswith("-"):
                item = stripped.lstrip("-").strip().strip("'\"")
                if item and item not in info.inherit_from:
                    info.inherit_from.append(item)

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                section,
                in_all_cops,
                in_exclude,
                in_inherit,
                in_require,
                current_cop,
            )

            if in_exclude and not stripped.startswith("-"):
                in_exclude = False
            if in_inherit and not stripped.startswith("-"):
                in_inherit = False
            if in_require and not stripped.startswith("-"):
                in_require = False

        return findings, info

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[RuboCopFinding],
        info: RuboCopInfo,
        section: str,
        in_all_cops: bool,
        in_exclude: bool,
        in_inherit: bool,
        in_require: bool,
        current_cop: str,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if SECURITY_COP_HEADER_PATTERN.match(stripped):
            current_cop = stripped.rstrip(":").strip()

        if SECURITY_COP_INLINE_PATTERN.match(stripped):
            cop = stripped.lstrip("-").strip()
            if cop not in info.disabled_cops:
                info.disabled_cops.append(cop)
            findings.append(
                RuboCopFinding(
                    kind="security_cop_excluded",
                    severity="high",
                    message=f"Security cop '{cop}' excluded — keep Security/* checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if current_cop.startswith("Security/") and ENABLED_FALSE_PATTERN.search(stripped):
            if current_cop not in info.disabled_cops:
                info.disabled_cops.append(current_cop)
            findings.append(
                RuboCopFinding(
                    kind="security_cop_disabled",
                    severity="high",
                    message=f"Security cop '{current_cop}' disabled — keep Security/* checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BUNDLER_INSECURE_DISABLED_PATTERN.match(stripped):
            cop = stripped.rstrip(":").strip()
            findings.append(
                RuboCopFinding(
                    kind="bundler_security_disabled",
                    severity="medium",
                    message=f"Bundler security cop '{cop}' configured — verify it stays enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RAILS_SECURITY_DISABLED_PATTERN.match(stripped):
            cop = stripped.rstrip(":").strip()
            findings.append(
                RuboCopFinding(
                    kind="rails_security_disabled",
                    severity="medium",
                    message=f"Rails security cop '{cop}' configured — verify CSP/SSL rules stay enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_exclude and EXCLUDE_SOURCE_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="AllCops Exclude omits source directories — narrow exclusions to vendor/tmp only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_exclude and EXCLUDE_BROAD_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="exclude_broad",
                    severity="high",
                    message="AllCops Exclude uses a broad wildcard — avoid excluding all source files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_inherit and INHERIT_HTTP_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="inherit_insecure_http",
                    severity="high",
                    message="inherit_from uses cleartext HTTP — use HTTPS or local config files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif in_inherit and INHERIT_REMOTE_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="inherit_remote",
                    severity="medium",
                    message="inherit_from pulls remote config — pin to a trusted commit or vendor locally",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                RuboCopFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in RuboCop config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                RuboCopFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in RuboCop config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line) and not in_inherit:
            findings.append(
                RuboCopFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in RuboCop config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_all_cops and DISABLED_BY_DEFAULT_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="disabled_by_default",
                    severity="high",
                    message="AllCops DisabledByDefault disables all cops — explicitly enable required checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_all_cops and NEW_COPS_DISABLE_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="new_cops_disabled",
                    severity="medium",
                    message="AllCops NewCops: disable misses new security cops — prefer enable or pending",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_all_cops and TARGET_RUBY_OLD_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="target_ruby_old",
                    severity="low",
                    message="TargetRubyVersion is outdated — upgrade to a supported Ruby release",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_all_cops and RUN_ALL_COPS_DISABLED_PATTERN.search(stripped):
            findings.append(
                RuboCopFinding(
                    kind="run_rails_cops_false",
                    severity="low",
                    message="RunRailsCops disabled — Rails security cops will not run",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                RuboCopFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in RuboCop config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_require and REQUIRE_GEM_PATTERN.search(stripped):
            gem = stripped.lstrip("-").strip().strip("'\"")
            findings.append(
                RuboCopFinding(
                    kind="require_gem",
                    severity="low",
                    message=f"require loads gem '{gem}' — verify it is trusted and pinned",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def analyze(self) -> list[RuboCopFinding]:
        """Scan RuboCop configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[RuboCopFinding] = []
        infos: list[RuboCopInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = RuboCopStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> RuboCopStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[RuboCopInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened RuboCop configuration template."""
        return """\
# Generated by DevAI RuboCopAnalyzer
inherit_mode:
  merge:
    - Exclude

AllCops:
  NewCops: enable
  TargetRubyVersion: 3.3
  Exclude:
    - 'vendor/**/*'
    - 'tmp/**/*'
    - 'node_modules/**/*'

require:
  - rubocop-rails
  - rubocop-performance
  - rubocop-security

Security/Eval:
  Enabled: true

Bundler/InsecureRubyProtocol:
  Enabled: true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "RuboCop configs: none found"
        return (
            f"RuboCop configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "RuboCop analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            disabled = ", ".join(info.disabled_cops) if info.disabled_cops else "none"
            excluded = ", ".join(info.excluded_paths) if info.excluded_paths else "none"
            lines.append(f"  - {info.path}: disabled=[{disabled}], excluded=[{excluded}]")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
