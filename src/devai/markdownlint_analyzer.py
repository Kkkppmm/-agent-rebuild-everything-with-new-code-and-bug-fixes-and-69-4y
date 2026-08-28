"""MarkdownlintAnalyzer — audit markdownlint configs for hygiene and security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".markdownlint.json",
    ".markdownlint.yaml",
    ".markdownlint.yml",
    ".markdownlintrc",
    ".markdownlintrc.json",
    ".markdownlintrc.yaml",
    ".markdownlintrc.yml",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
MD033_DISABLED_PATTERN = re.compile(
    r'["\']?MD033["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
MD013_DISABLED_PATTERN = re.compile(
    r'["\']?MD013["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
MD036_DISABLED_PATTERN = re.compile(
    r'["\']?MD036["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
MD045_DISABLED_PATTERN = re.compile(
    r'["\']?MD045["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
MD046_DISABLED_PATTERN = re.compile(
    r'["\']?MD046["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
DEFAULT_DISABLED_PATTERN = re.compile(
    r'["\']?default["\']?\s*:\s*(?:false|0|off)',
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r'["\']?line_length["\']?\s*:\s*(?:2[0-9]{3}|[3-9][0-9]{3,})',
    re.IGNORECASE,
)
ALLOWED_ELEMENTS_ALL_PATTERN = re.compile(
    r'["\']?allowed_elements["\']?\s*:\s*\[[^\]]*["\']\*["\']',
    re.IGNORECASE,
)
IGNORE_GLOB_BROAD_PATTERN = re.compile(
    r'["\']?ignores["\']?\s*:\s*\[[^\]]*["\']\*\*?/?\*["\']',
    re.IGNORECASE,
)


@dataclass
class MarkdownlintFinding:
    """A security or best-practice issue in a markdownlint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MarkdownlintInfo:
    """Parsed metadata about a markdownlint configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    default_enabled: bool = True
    disabled_rules: list[str] = field(default_factory=list)


@dataclass
class MarkdownlintStats:
    """Aggregate markdownlint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    if name.endswith(".json") or name == ".markdownlintrc":
        return "json"
    return "unknown"


def _extract_disabled_rule(line: str) -> str | None:
    match = re.search(r'["\']?(MD\d{3})["\']?\s*:\s*(?:false|0|off)\b', line, re.IGNORECASE)
    return match.group(1).upper() if match else None


class MarkdownlintAnalyzer:
    """Audit markdownlint configuration for security and documentation hygiene risks.

    Scans .markdownlint.* configs for disabled HTML/URL rules, broad ignore globs,
    hardcoded secrets, and permissive allowed_elements settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MarkdownlintFinding] | None = None
        self._stats: MarkdownlintStats | None = None
        self._infos: list[MarkdownlintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return markdownlint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MarkdownlintFinding],
        info: MarkdownlintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        disabled_rule = _extract_disabled_rule(stripped)
        if disabled_rule and disabled_rule not in info.disabled_rules:
            info.disabled_rules.append(disabled_rule)

        if DEFAULT_DISABLED_PATTERN.search(stripped):
            info.default_enabled = False

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in markdownlint config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in markdownlint config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in markdownlint config — use HTTPS endpoints"),
            (MD033_DISABLED_PATTERN, "md033_disabled", "high",
             "MD033 disabled allows raw HTML injection in markdown docs"),
            (MD045_DISABLED_PATTERN, "md045_disabled", "medium",
             "MD045 disabled skips alt-text checks on images"),
            (MD013_DISABLED_PATTERN, "md013_disabled", "low",
             "MD013 disabled allows very long lines that hide malicious content"),
            (MD036_DISABLED_PATTERN, "md036_disabled", "low",
             "MD036 disabled allows emphasis used as headings"),
            (MD046_DISABLED_PATTERN, "md046_disabled", "medium",
             "MD046 disabled allows inconsistent code fence styles"),
            (DEFAULT_DISABLED_PATTERN, "default_disabled", "high",
             "default:false disables all markdownlint rules"),
            (LINE_LENGTH_HIGH_PATTERN, "line_length_high", "low",
             "line_length > 2000 reduces reviewability of markdown changes"),
            (ALLOWED_ELEMENTS_ALL_PATTERN, "allowed_elements_all", "high",
             "allowed_elements:* permits arbitrary HTML in markdown"),
            (IGNORE_GLOB_BROAD_PATTERN, "ignore_glob_broad", "medium",
             "broad ignores glob skips linting on documentation files"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    MarkdownlintFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[MarkdownlintFinding], MarkdownlintInfo]:
        findings: list[MarkdownlintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MarkdownlintInfo(path=rel, file_kind=_file_kind(path))

        info = MarkdownlintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)
        return findings, info

    def analyze(self) -> list[MarkdownlintFinding]:
        """Scan markdownlint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MarkdownlintFinding] = []
        infos: list[MarkdownlintInfo] = []
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
        self._stats = MarkdownlintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MarkdownlintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MarkdownlintInfo]:
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
        """Scaffold a hardened markdownlint configuration template."""
        return """\
{
  "default": true,
  "MD013": { "line_length": 120 },
  "MD033": { "allowed_elements": ["details", "summary"] },
  "MD045": true,
  "MD046": { "style": "fenced" }
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Markdownlint configs: none found"
        return (
            f"Markdownlint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Markdownlint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            disabled = ", ".join(info.disabled_rules) if info.disabled_rules else "none"
            lines.append(f"  - {info.path}: disabled rules={disabled}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
