"""GolangciLintAnalyzer — audit golangci-lint configs for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".golangci.yml",
    ".golangci.yaml",
    ".golangci.toml",
    "golangci.yml",
    "golangci.yaml",
    "golangci.toml",
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
DISABLE_ALL_PATTERN = re.compile(
    r"^\s*disable-all\s*:\s*true\s*$",
    re.IGNORECASE,
)
DISABLED_SECURITY_LINTER_PATTERN = re.compile(
    r"^\s*-\s*(?:gosec|bodyclose|sqlclosecheck|rowserrcheck|noctx|errchkjson|"
    r"exportloopref|gocritic|staticcheck|govet|errcheck)\s*$",
    re.IGNORECASE,
)
DISABLE_SECURITY_LINE_PATTERN = re.compile(
    r"^\s*disable\s*:\s*[^\n#]*\b(?:gosec|bodyclose|sqlclosecheck|rowserrcheck|noctx)\b",
    re.IGNORECASE,
)
SKIP_DIRS_SOURCE_PATTERN = re.compile(
    r"^\s*-\s*(?:src|lib|internal|cmd|pkg)\s*$",
    re.IGNORECASE,
)
SKIP_FILES_BROAD_PATTERN = re.compile(
    r"^\s*-\s*(?:\.\*|.*\.go|.*)\s*$",
    re.IGNORECASE,
)
GOSEC_EXCLUDES_PATTERN = re.compile(
    r"^\s*-\s*G\d{3}\b",
    re.IGNORECASE,
)
BROAD_EXCLUDE_TEXT_PATTERN = re.compile(
    r"^\s*(?:-\s*)?text\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
EXCLUDE_USE_DEFAULT_PATTERN = re.compile(
    r"^\s*exclude-use-default\s*:\s*true\s*$",
    re.IGNORECASE,
)
TIMEOUT_HIGH_PATTERN = re.compile(
    r"^\s*timeout\s*:\s*(?:[3-9][0-9]m|[1-9][0-9]{2,}m|[1-9]h)\s*$",
    re.IGNORECASE,
)
ALLOW_PARALLEL_RUNNERS_PATTERN = re.compile(
    r"^\s*allow-parallel-runners\s*:\s*true\s*$",
    re.IGNORECASE,
)
BUILD_TAGS_ITEM_PATTERN = re.compile(
    r"^\s*-\s*(?:debug|integration|unsafe)\s*$",
    re.IGNORECASE,
)
INSECURE_RUN_MODE_PATTERN = re.compile(
    r"^\s*modules-download-mode\s*:\s*(?:mod|vendor)\s*$",
    re.IGNORECASE,
)


@dataclass
class GolangciFinding:
    """A security or best-practice issue in a golangci-lint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class GolangciInfo:
    """Parsed metadata about a golangci-lint configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    enabled_linters: list[str] = field(default_factory=list)
    disabled_linters: list[str] = field(default_factory=list)


@dataclass
class GolangciStats:
    """Aggregate golangci-lint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".yml", ".yaml"):
        return "yaml"
    if suffix == ".toml":
        return "toml"
    return "unknown"


class GolangciLintAnalyzer:
    """Audit golangci-lint configuration for lint hygiene and security risks.

    Scans .golangci.yml, .golangci.yaml, and .golangci.toml for broad disable
    patterns, disabled security linters, source tree exclusions, gosec rule
    suppressions, hardcoded secrets, and overly permissive run settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GolangciFinding] | None = None
        self._stats: GolangciStats | None = None
        self._infos: list[GolangciInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return golangci-lint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GolangciFinding], GolangciInfo]:
        findings: list[GolangciFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GolangciInfo(path=rel, file_kind=_file_kind(path))

        info = GolangciInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        section = ""
        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.endswith(":") and not stripped.startswith("-"):
                section = stripped.rstrip(":").lower()
                self._scan_line(line, lineno, rel, findings, info, section)
                continue

            self._scan_line(line, lineno, rel, findings, info, section)
        return findings, info

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GolangciFinding],
        info: GolangciInfo,
        section: str,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        list_match = re.match(r"^\s*-\s*([a-zA-Z0-9_*.-]+)\s*$", stripped)
        if list_match:
            item = list_match.group(1).lower()
            if section.endswith("enable"):
                if item not in info.enabled_linters:
                    info.enabled_linters.append(item)
            elif section.endswith("disable"):
                if item not in info.disabled_linters:
                    info.disabled_linters.append(item)
                if DISABLED_SECURITY_LINTER_PATTERN.match(stripped):
                    findings.append(
                        GolangciFinding(
                            kind="disabled_security_linter",
                            severity="high",
                            message=f"security linter '{item}' disabled — keep gosec and related checks enabled",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
            elif section.endswith("skip-dirs") and SKIP_DIRS_SOURCE_PATTERN.search(stripped):
                findings.append(
                    GolangciFinding(
                        kind="skip_dirs_source",
                        severity="medium",
                        message="run.skip-dirs omits source directories — narrow skips to generated/vendor paths only",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif section.endswith("skip-files") and SKIP_FILES_BROAD_PATTERN.search(stripped):
                findings.append(
                    GolangciFinding(
                        kind="skip_files_broad",
                        severity="medium",
                        message="run.skip-files uses a broad pattern — avoid skipping all Go source files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif section.endswith("excludes") and GOSEC_EXCLUDES_PATTERN.search(stripped):
                findings.append(
                    GolangciFinding(
                        kind="gosec_excludes",
                        severity="high",
                        message="gosec rule excluded — prefer fixing issues over suppressing security checks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif section.endswith("build-tags") and BUILD_TAGS_ITEM_PATTERN.search(stripped):
                findings.append(
                    GolangciFinding(
                        kind="build_tags_risky",
                        severity="medium",
                        message="run.build-tags includes debug/integration/unsafe tags — verify production builds exclude them",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in golangci-lint config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in golangci-lint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in golangci-lint config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_ALL_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="disable_all",
                    severity="high",
                    message="linters.disable-all disables all linters — explicitly enable required checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_SECURITY_LINE_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="disabled_security_linter",
                    severity="high",
                    message="security linters disabled in disable list — keep gosec and related checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROAD_EXCLUDE_TEXT_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="broad_exclude_rule",
                    severity="medium",
                    message="issues.exclude-rules uses wildcard text — narrow exclusions to specific patterns",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_USE_DEFAULT_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="exclude_use_default",
                    severity="low",
                    message="exclude-use-default adds stock suppressions — review custom exclude-rules carefully",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TIMEOUT_HIGH_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="timeout_high",
                    severity="low",
                    message="run.timeout > 30m can hide slow CI jobs — tighten for faster feedback",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_PARALLEL_RUNNERS_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="allow_parallel_runners",
                    severity="low",
                    message="allow-parallel-runners can increase CI resource usage — enable only when needed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_RUN_MODE_PATTERN.search(line):
            findings.append(
                GolangciFinding(
                    kind="modules_download_mode",
                    severity="low",
                    message="modules-download-mode set — ensure vendor/mod mode matches your supply-chain policy",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def analyze(self) -> list[GolangciFinding]:
        """Scan golangci-lint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GolangciFinding] = []
        infos: list[GolangciInfo] = []
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
        self._stats = GolangciStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GolangciStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GolangciInfo]:
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
        """Scaffold a hardened golangci-lint configuration template."""
        return """\
# Generated by DevAI GolangciLintAnalyzer
run:
  timeout: 5m
  tests: true
  modules-download-mode: readonly

linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gosec
    - bodyclose
    - noctx
    - rowserrcheck
    - sqlclosecheck

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
  max-same-issues: 0
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "golangci-lint configs: none found"
        return (
            f"golangci-lint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "golangci-lint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            enabled = ", ".join(info.enabled_linters) if info.enabled_linters else "default"
            disabled = ", ".join(info.disabled_linters) if info.disabled_linters else "none"
            lines.append(f"  - {info.path}: enabled=[{enabled}], disabled=[{disabled}]")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
