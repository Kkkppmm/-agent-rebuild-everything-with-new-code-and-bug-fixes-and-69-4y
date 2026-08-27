"""YamllintAnalyzer — audit yamllint configs for disabled truthy/key-duplicates checks and broad ignores."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".yamllint",
    ".yamllint.yaml",
    ".yamllint.yml",
    "yamllint.yaml",
    "yamllint.yml",
    "pyproject.toml",
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
TRUTHY_DISABLED_PATTERN = re.compile(
    r"truthy\s*[:=]\s*(?:false|(?:\{[^\}]*enabled\s*[:=]\s*false))",
    re.IGNORECASE,
)
KEY_DUPLICATES_DISABLED_PATTERN = re.compile(
    r"key-duplicates\s*[:=]\s*(?:false|(?:\{[^\}]*enabled\s*[:=]\s*false))",
    re.IGNORECASE,
)
ENABLED_FALSE_PATTERN = re.compile(r"enabled\s*[:=]\s*false\b", re.IGNORECASE)
FORBID_EMPTY_FALSE_PATTERN = re.compile(
    r"forbid-in-block-mappings\s*[:=]\s*false\b",
    re.IGNORECASE,
)
LINE_LENGTH_MAX_HIGH_PATTERN = re.compile(
    r"max\s*[:=]\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
BROAD_IGNORE_PATTERN = re.compile(
    r"ignore\s*:\s*(?:\||>|-)?\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
IGNORE_ALL_FILES_PATTERN = re.compile(
    r"ignore\s*:\s*(?:\||>|-)?\s*[\"']?(?:\*\.\*|/\*\*|all)[\"']?",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"line-length\s*[:=]\s*(?:\{[^\}]*max\s*[:=]\s*)?(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
DOCUMENT_START_DISABLED_PATTERN = re.compile(
    r"document-start\s*[:=]\s*(?:false|(?:\{[^\}]*present\s*[:=]\s*false))",
    re.IGNORECASE,
)
EMPTY_VALUES_DISABLED_PATTERN = re.compile(
    r"empty-values\s*[:=]\s*(?:false|(?:\{[^\}]*forbid-in-block-mappings\s*[:=]\s*false))",
    re.IGNORECASE,
)
COMMENTS_IGNORE_BROAD_PATTERN = re.compile(
    r"ignore\s*[:=]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
YAMLLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]yamllint(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
YAMLLINT_RULE_NAMES = frozenset(
    {
        "truthy",
        "key-duplicates",
        "line-length",
        "document-start",
        "empty-values",
        "comments",
        "braces",
        "brackets",
        "colons",
        "commas",
        "comments-indentation",
        "document-end",
        "empty-lines",
        "float-values",
        "hyphens",
        "indentation",
        "key-ordering",
        "new-line-at-end-of-file",
        "new-lines",
        "octal-values",
        "quoted-strings",
        "trailing-spaces",
    }
)


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
    extends: str = ""
    rules: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


@dataclass
class YamllintStats:
    """Aggregate yamllint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.name.endswith(".toml"):
        return "toml"
    if path.name.endswith((".yaml", ".yml")) or path.name == ".yamllint":
        return "yaml"
    return "unknown"


def _extract_yaml_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*:\s*(.+?)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    value = match.group(1).strip().strip("\"'")
    return value or None


class YamllintAnalyzer:
    """Audit yamllint configuration for security and YAML hygiene risks.

    Scans .yamllint and pyproject.toml [tool.yamllint] sections for disabled
    truthy/key-duplicates checks, broad ignore patterns, hardcoded secrets, and
    unsafe line-length or document-start settings.
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
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if name == "pyproject.toml":
                if "[tool.yamllint" not in text and "[tool:yamllint" not in text:
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
        parent_rule: str | None = None,
    ) -> str | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return parent_rule

        section_match = YAMLLINT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        extends = _extract_yaml_value(stripped, "extends")
        if extends:
            info.extends = extends

        rule_match = re.match(r"^([a-z][a-z0-9-]*)\s*[:=]", stripped, re.IGNORECASE)
        current_rule = parent_rule
        if rule_match:
            key = rule_match.group(1)
            if key in YAMLLINT_RULE_NAMES:
                current_rule = key
                if key not in info.rules:
                    info.rules.append(key)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in yamllint config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in yamllint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in yamllint config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRUTHY_DISABLED_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — allows yes/no/on/off coercion bugs in YAML",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if KEY_DUPLICATES_DISABLED_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates rule disabled — duplicate keys can silently override values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif current_rule == "key-duplicates" and ENABLED_FALSE_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates rule disabled — duplicate keys can silently override values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if current_rule == "truthy" and ENABLED_FALSE_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — allows yes/no/on/off coercion bugs in YAML",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if current_rule == "comments" and COMMENTS_IGNORE_BROAD_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="comments_ignore_broad",
                    severity="low",
                    message="comments.ignore=* suppresses comment linting across all files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROAD_IGNORE_PATTERN.search(line) or IGNORE_ALL_FILES_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="broad_ignore",
                    severity="medium",
                    message="broad ignore pattern skips YAML linting — narrow to specific paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_HIGH_PATTERN.search(line) or (
            current_rule == "line-length" and LINE_LENGTH_MAX_HIGH_PATTERN.search(line)
        ):
            findings.append(
                YamllintFinding(
                    kind="line_length_high",
                    severity="medium",
                    message="line-length max > 200 reduces readability — use 80-120",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOCUMENT_START_DISABLED_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="document_start_disabled",
                    severity="low",
                    message="document-start disabled — explicit --- markers improve YAML clarity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EMPTY_VALUES_DISABLED_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="empty_values_disabled",
                    severity="medium",
                    message="empty-values rule disabled — empty mappings can hide config mistakes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif current_rule == "empty-values" and FORBID_EMPTY_FALSE_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="empty_values_disabled",
                    severity="medium",
                    message="empty-values rule disabled — empty mappings can hide config mistakes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return current_rule

    def _analyze_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        findings: list[YamllintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, YamllintInfo(path=rel, file_kind=_file_kind(path))

        info = YamllintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_yamllint_section = path.name != "pyproject.toml"
        parent_rule: str | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                if YAMLLINT_SECTION_PATTERN.match(line.strip()):
                    in_yamllint_section = True
                elif line.strip().startswith("[") and not YAMLLINT_SECTION_PATTERN.match(line.strip()):
                    in_yamllint_section = False
                if not in_yamllint_section:
                    continue
            parent_rule = self._scan_line(line, lineno, rel, findings, info, parent_rule)

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

rules:
  truthy:
    enabled: true
  key-duplicates:
    enabled: true
  empty-values:
    forbid-in-block-mappings: true
  line-length:
    max: 120
  document-start:
    present: false
  comments:
    ignore: |
      ^# SPDX-License-Identifier
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
            extends = info.extends or "none"
            rules = ", ".join(info.rules[:8]) if info.rules else "default"
            lines.append(f"  - {info.path}: extends={extends}, rules={rules}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
