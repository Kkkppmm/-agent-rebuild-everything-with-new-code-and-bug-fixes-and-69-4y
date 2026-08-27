"""YamllintAnalyzer — audit yamllint configs for disabled checks and broad ignores."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".yamllint",
    ".yamllint.yaml",
    ".yamllint.yml",
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
TRUTHY_DISABLE_PATTERN = re.compile(
    r"^\s*truthy\s*:\s*disable\s*$",
    re.IGNORECASE,
)
TRUTHY_ENABLED_FALSE_PATTERN = re.compile(
    r"^\s*enabled\s*:\s*false\s*$",
    re.IGNORECASE,
)
KEY_DUPLICATES_DISABLE_PATTERN = re.compile(
    r"^\s*key-duplicates\s*:\s*disable\s*$",
    re.IGNORECASE,
)
KEY_DUPLICATES_ENABLED_FALSE_PATTERN = re.compile(
    r"^\s*key-duplicates\s*:.*$",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"^\s*max\s*:\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\s*$",
    re.IGNORECASE,
)
BROAD_IGNORE_PATTERN = re.compile(
    r"(?:^ignore\s*:\s*[\"']?\*\*|^\s+\*\*/?\*|\*\*/\*\s*$)",
    re.IGNORECASE,
)
RELAXED_EXTENDS_PATTERN = re.compile(
    r"^\s*extends\s*:\s*(?:relaxed|custom)\s*$",
    re.IGNORECASE,
)
EMPTY_DOCUMENT_DISABLE_PATTERN = re.compile(
    r"^\s*empty-values\s*:\s*disable\s*$",
    re.IGNORECASE,
)
COMMENTS_DISABLE_PATTERN = re.compile(
    r"^\s*comments(?:-indentation)?\s*:\s*disable\s*$",
    re.IGNORECASE,
)
YAMLLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]yamllint(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
YAMLLINT_TRUTHY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]yamllint(?:\.[^\]]*truthy[^\]]*)?)\]",
    re.IGNORECASE,
)
YAMLLINT_KEY_DUPLICATES_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]yamllint(?:\.[^\]]*key-duplicates[^\]]*)?)\]",
    re.IGNORECASE,
)
TOML_ENABLED_FALSE_PATTERN = re.compile(r"^\s*enabled\s*=\s*false\s*$", re.IGNORECASE)


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
    disabled_rules: list[str] = field(default_factory=list)
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
    if path.name == "pyproject.toml":
        return "toml"
    if path.suffix in (".yaml", ".yml") or path.name == ".yamllint":
        return "yaml"
    return "unknown"


class YamllintAnalyzer:
    """Audit yamllint configuration for security and linting hygiene risks.

    Scans .yamllint, .yamllint.yaml, .yamllint.yml, and pyproject.toml
    [tool.yamllint] sections for disabled truthy/key-duplicates checks,
    broad ignore patterns, hardcoded secrets, and relaxed rule sets.
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

    def _scan_yaml_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
        in_truthy_block: bool,
        in_key_duplicates_block: bool,
    ) -> tuple[bool, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return in_truthy_block, in_key_duplicates_block

        if stripped.startswith("extends:"):
            extends_val = stripped.split(":", 1)[1].strip()
            info.extends = extends_val
            if RELAXED_EXTENDS_PATTERN.match(stripped):
                findings.append(
                    YamllintFinding(
                        kind="relaxed_extends",
                        severity="medium",
                        message="extends: relaxed/custom weakens YAML validation — prefer default rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if TRUTHY_DISABLE_PATTERN.match(stripped):
            info.disabled_rules.append("truthy")
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — YAML truthy values can hide CI misconfigurations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if stripped.startswith("truthy:") and stripped.endswith(":"):
            in_truthy_block = True
            in_key_duplicates_block = False
        elif stripped.startswith("key-duplicates:") and stripped.endswith(":"):
            in_key_duplicates_block = True
            in_truthy_block = False
        elif not line.startswith(" ") and not line.startswith("\t"):
            in_truthy_block = False
            in_key_duplicates_block = False

        if in_truthy_block and TRUTHY_ENABLED_FALSE_PATTERN.match(stripped):
            info.disabled_rules.append("truthy")
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — YAML truthy values can hide CI misconfigurations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if KEY_DUPLICATES_DISABLE_PATTERN.match(stripped):
            info.disabled_rules.append("key-duplicates")
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates disabled — duplicate keys can mask malicious overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_key_duplicates_block and TRUTHY_ENABLED_FALSE_PATTERN.match(stripped):
            info.disabled_rules.append("key-duplicates")
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates disabled — duplicate keys can mask malicious overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_HIGH_PATTERN.match(stripped):
            findings.append(
                YamllintFinding(
                    kind="line_length_high",
                    severity="medium",
                    message="line-length max > 200 reduces readability — use 80-120 for CI configs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROAD_IGNORE_PATTERN.search(line):
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

        if EMPTY_DOCUMENT_DISABLE_PATTERN.match(stripped):
            info.disabled_rules.append("empty-values")
            findings.append(
                YamllintFinding(
                    kind="empty_values_disabled",
                    severity="low",
                    message="empty-values disabled — empty documents may hide config errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COMMENTS_DISABLE_PATTERN.match(stripped):
            info.disabled_rules.append("comments")
            findings.append(
                YamllintFinding(
                    kind="comments_disabled",
                    severity="low",
                    message="comments rule disabled — comment formatting issues may go unnoticed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

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

        return in_truthy_block, in_key_duplicates_block

    def _scan_toml_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        section_match = YAMLLINT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if re.search(r"truthy\s*=\s*false\b", stripped, re.IGNORECASE):
            info.disabled_rules.append("truthy")
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — YAML truthy values can hide CI misconfigurations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"key-duplicates\s*=\s*false\b", stripped, re.IGNORECASE):
            info.disabled_rules.append("key-duplicates")
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates disabled — duplicate keys can mask malicious overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

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

    def _analyze_yaml_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        findings: list[YamllintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, YamllintInfo(path=rel, file_kind=_file_kind(path))

        info = YamllintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_truthy = False
        in_key_duplicates = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_truthy, in_key_duplicates = self._scan_yaml_line(
                line, lineno, rel, findings, info, in_truthy, in_key_duplicates
            )

        return findings, info

    def _analyze_toml_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        findings: list[YamllintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, YamllintInfo(path=rel, file_kind=_file_kind(path))

        info = YamllintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_yamllint_section = False
        in_truthy_section = False
        in_key_duplicates_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if YAMLLINT_TRUTHY_SECTION_PATTERN.match(stripped):
                in_yamllint_section = True
                in_truthy_section = True
                in_key_duplicates_section = False
            elif YAMLLINT_KEY_DUPLICATES_SECTION_PATTERN.match(stripped):
                in_yamllint_section = True
                in_key_duplicates_section = True
                in_truthy_section = False
            elif YAMLLINT_SECTION_PATTERN.match(stripped):
                in_yamllint_section = True
                in_truthy_section = False
                in_key_duplicates_section = False
            elif stripped.startswith("[") and not YAMLLINT_SECTION_PATTERN.match(stripped):
                in_yamllint_section = False
                in_truthy_section = False
                in_key_duplicates_section = False

            if not in_yamllint_section:
                continue

            if in_truthy_section and TOML_ENABLED_FALSE_PATTERN.match(stripped):
                info.disabled_rules.append("truthy")
                findings.append(
                    YamllintFinding(
                        kind="truthy_disabled",
                        severity="high",
                        message="truthy rule disabled — YAML truthy values can hide CI misconfigurations",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_key_duplicates_section and TOML_ENABLED_FALSE_PATTERN.match(stripped):
                info.disabled_rules.append("key-duplicates")
                findings.append(
                    YamllintFinding(
                        kind="key_duplicates_disabled",
                        severity="high",
                        message="key-duplicates disabled — duplicate keys can mask malicious overrides",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            self._scan_toml_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        if _file_kind(path) == "toml":
            return self._analyze_toml_file(path)
        return self._analyze_yaml_file(path)

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
    check-keys: true
  key-duplicates: enable
  line-length:
    max: 120
    level: warning
  comments-indentation: enable
  empty-values:
    forbid-in-block-mappings: true
    forbid-in-flow-mappings: true

ignore: |
  .git/
  .venv/
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
            disabled = ", ".join(info.disabled_rules) if info.disabled_rules else "none"
            lines.append(f"  - {info.path}: extends={extends}, disabled={disabled}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
