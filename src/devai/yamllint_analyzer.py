"""YamllintAnalyzer — audit yamllint configs for disabled truthy/key-duplicates checks and broad ignores."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".yamllint",
    ".yamllint.yaml",
    ".yamllint.yml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
EXTENDS_RELAXED_PATTERN = re.compile(
    r"^\s*extends\s*:\s*relaxed\s*$",
    re.IGNORECASE,
)
TRUTHY_CHECK_KEYS_FALSE_PATTERN = re.compile(
    r"^\s*check-keys\s*:\s*false\s*$",
    re.IGNORECASE,
)
TRUTHY_DISABLED_PATTERN = re.compile(
    r"^\s*truthy\s*:\s*disable\s*$",
    re.IGNORECASE,
)
KEY_DUPLICATES_DISABLED_PATTERN = re.compile(
    r"^\s*key-duplicates\s*:\s*disable\s*$",
    re.IGNORECASE,
)
RULE_LEVEL_DISABLE_PATTERN = re.compile(
    r"^\s*level\s*:\s*disable\s*$",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"^\s*max\s*:\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\s*$",
    re.IGNORECASE,
)
BROAD_IGNORE_PATTERN = re.compile(
    r"^\s*ignore\s*:\s*\|?\s*$|"
    r"^\s*ignore\s*:\s*[\"']?\*[\"']?\s*$|"
    r"^\s*ignore\s*:\s*\[[^\]]*[\"'](?:\*|\.github|\.gitlab-ci\.yml|k8s|deploy)[\"']",
    re.IGNORECASE,
)
DOCUMENT_START_DISABLED_PATTERN = re.compile(
    r"^\s*document-start\s*:\s*disable\s*$",
    re.IGNORECASE,
)
EMPTY_VALUES_DISABLED_PATTERN = re.compile(
    r"^\s*empty-values\s*:\s*disable\s*$",
    re.IGNORECASE,
)
COMMENTS_DISABLED_PATTERN = re.compile(
    r"^\s*comments\s*:\s*disable\s*$",
    re.IGNORECASE,
)
RULES_SECTION_PATTERN = re.compile(r"^\s*rules\s*:\s*$", re.IGNORECASE)
TRUTHY_SECTION_PATTERN = re.compile(r"^\s*truthy\s*:\s*$", re.IGNORECASE)
KEY_DUPLICATES_SECTION_PATTERN = re.compile(r"^\s*key-duplicates\s*:\s*$", re.IGNORECASE)
LINE_LENGTH_SECTION_PATTERN = re.compile(r"^\s*line-length\s*:\s*$", re.IGNORECASE)


@dataclass
class YamllintFinding:
    """A security or best-practice issue in a yamllint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class YamllintInfo:
    """Parsed metadata about a yamllint configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    extends: str | None = None
    rules: list[str] = field(default_factory=list)
    ignore_patterns: list[str] = field(default_factory=list)


@dataclass
class YamllintStats:
    """Aggregate yamllint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.suffix in {".yaml", ".yml"} or path.name == ".yamllint":
        return "yaml"
    return "unknown"


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class YamllintAnalyzer:
    """Audit yamllint configuration for security and YAML hygiene risks.

    Scans .yamllint and .yamllint.{yaml,yml} for disabled truthy/key-duplicates
    checks, broad ignore patterns, hardcoded secrets, and relaxed rule presets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[YamllintFinding] | None = None
        self._stats: YamllintStats | None = None
        self._infos: list[YamllintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return yamllint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[YamllintFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        line: str,
    ) -> None:
        findings.append(
            YamllintFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=line,
            )
        )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
        *,
        in_rules: bool,
        in_truthy: bool,
        in_key_duplicates: bool,
        in_line_length: bool,
    ) -> tuple[bool, bool, bool, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return in_rules, in_truthy, in_key_duplicates, in_line_length

        if RULES_SECTION_PATTERN.match(stripped):
            return True, False, False, False
        if TRUTHY_SECTION_PATTERN.match(stripped):
            return in_rules, True, False, False
        if KEY_DUPLICATES_SECTION_PATTERN.match(stripped):
            return in_rules, False, True, False
        if LINE_LENGTH_SECTION_PATTERN.match(stripped):
            return in_rules, False, False, True

        if stripped and not line.startswith(" ") and not line.startswith("\t"):
            if not stripped.startswith("-"):
                in_truthy = False
                in_key_duplicates = False
                in_line_length = False

        extends_match = re.match(r"^\s*extends\s*:\s*(\S+)\s*$", stripped, re.IGNORECASE)
        if extends_match:
            info.extends = extends_match.group(1)

        rule_match = re.match(r"^\s*([a-z0-9-]+)\s*:\s*(disable|enable|warning|error)\s*$", stripped, re.IGNORECASE)
        if rule_match and in_rules:
            info.rules.append(rule_match.group(1))

        ignore_match = re.match(r"^\s*-\s*[\"']?([^\"'\s]+)[\"']?\s*$", stripped)
        if ignore_match:
            info.ignore_patterns.append(ignore_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="hardcoded_secret",
                severity="high",
                message="hardcoded secret in yamllint config — use env vars or CI secrets",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="aws_access_key",
                severity="high",
                message="AWS access key in yamllint config — rotate and use env vars",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if INSECURE_HTTP_PATTERN.search(line):
            self._add_finding(
                findings,
                kind="insecure_http",
                severity="medium",
                message="insecure HTTP URL in yamllint config — use HTTPS endpoints",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if EXTENDS_RELAXED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="extends_relaxed",
                severity="medium",
                message="extends: relaxed weakens YAML validation — prefer default rules",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if TRUTHY_CHECK_KEYS_FALSE_PATTERN.match(stripped) or (
            in_truthy and TRUTHY_CHECK_KEYS_FALSE_PATTERN.search(stripped)
        ):
            self._add_finding(
                findings,
                kind="truthy_check_keys_disabled",
                severity="high",
                message="check-keys: false allows truthy key injection — keep check-keys enabled",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if TRUTHY_DISABLED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="truthy_disabled",
                severity="high",
                message="truthy rule disabled — re-enable to catch yes/on YAML coercion bugs",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if KEY_DUPLICATES_DISABLED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="key_duplicates_disabled",
                severity="high",
                message="key-duplicates disabled — duplicate keys can silently override values",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if in_key_duplicates and RULE_LEVEL_DISABLE_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="key_duplicates_disabled",
                severity="high",
                message="key-duplicates level: disable — duplicate keys can silently override values",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if in_line_length and LINE_LENGTH_HIGH_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="line_length_high",
                severity="medium",
                message="line-length max > 200 reduces reviewability — use 80-120 for CI configs",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if BROAD_IGNORE_PATTERN.search(stripped):
            self._add_finding(
                findings,
                kind="broad_ignore",
                severity="medium",
                message="broad ignore patterns skip CI/CD or deployment YAML from linting",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if DOCUMENT_START_DISABLED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="document_start_disabled",
                severity="low",
                message="document-start disabled — enabling helps detect multi-document injection",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if EMPTY_VALUES_DISABLED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="empty_values_disabled",
                severity="medium",
                message="empty-values disabled — empty YAML values can hide misconfigurations",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        if COMMENTS_DISABLED_PATTERN.match(stripped):
            self._add_finding(
                findings,
                kind="comments_disabled",
                severity="low",
                message="comments rule disabled — comment injection in YAML may go unnoticed",
                rel=rel,
                lineno=lineno,
                line=line,
            )

        return in_rules, in_truthy, in_key_duplicates, in_line_length

    def _analyze_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        findings: list[YamllintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, YamllintInfo(path=rel, file_kind=_file_kind(path))

        info = YamllintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_rules = False
        in_truthy = False
        in_key_duplicates = False
        in_line_length = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_rules, in_truthy, in_key_duplicates, in_line_length = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_rules=in_rules,
                in_truthy=in_truthy,
                in_key_duplicates=in_key_duplicates,
                in_line_length=in_line_length,
            )

        return findings, info

    def analyze(self) -> list[YamllintFinding]:
        """Scan yamllint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[YamllintFinding] = []
        infos: list[YamllintInfo] = []
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
        self._stats = YamllintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> YamllintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[YamllintInfo]:
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
        """Scaffold a hardened yamllint configuration template."""
        return """\
# Generated by DevAI YamllintAnalyzer
extends: default

ignore: |
  .git/
  .venv/
  node_modules/
  dist/
  build/

rules:
  line-length:
    max: 120
    level: warning
  truthy:
    check-keys: true
    allowed-values: ['true', 'false', 'on', 'off']
  key-duplicates: enable
  document-start: disable
  empty-values:
    forbid-in-block-mappings: true
    forbid-in-flow-mappings: true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Yamllint configs: none found"
        return (
            f"Yamllint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Yamllint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            extends = info.extends or "default"
            rules = ", ".join(info.rules) if info.rules else "default"
            lines.append(f"  - {info.path}: extends={extends}, rules={rules}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
