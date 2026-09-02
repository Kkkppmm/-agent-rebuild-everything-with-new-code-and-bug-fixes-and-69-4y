"""MarkdownlintAnalyzer — audit markdownlint configuration files for hygiene and security risks."""

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DEFAULT_FALSE_PATTERN = re.compile(
    r'["\']?default["\']?\s*:\s*(?:false|0|"off")',
    re.IGNORECASE,
)
RULE_DISABLE_PATTERN = re.compile(
    r'["\']?(MD\d{3})["\']?\s*:\s*(?:false|0|"off")',
    re.IGNORECASE,
)
RULE_DISABLE_YAML_PATTERN = re.compile(
    r"^\s*(MD\d{3})\s*:\s*(?:false|0|off)\s*(?:#.*)?$",
    re.IGNORECASE,
)
WILDCARD_RULE_DISABLE_PATTERN = re.compile(
    r'["\']?(MD[^"\']*\*[^"\']*)["\']?\s*:\s*(?:false|0|"off")',
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r'["\']?line[_-]?length["\']?\s*:\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b',
    re.IGNORECASE,
)
IGNORE_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'])(?:security|docs/security|\.github|policies|compliance|"
    r"audit|legal)(?:/|[\s\"']|$)",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r'["\']?ignores?["\']?\s*:\s*[^\n]*\*',
    re.IGNORECASE,
)

INLINE_HTML_RULES = frozenset({"MD033"})
ALT_TEXT_RULES = frozenset({"MD045"})
LINK_RULES = frozenset({"MD034", "MD051", "MD052"})
HEADING_RULES = frozenset({"MD024", "MD041", "MD025"})
STRUCTURE_RULES = frozenset({"MD046", "MD048"})


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
    default_enabled: bool | None = None
    disabled_rules: list[str] = field(default_factory=list)
    line_length_max: int | None = None
    has_ignore: bool = False


@dataclass
class MarkdownlintStats:
    """Aggregate markdownlint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_markdownlint_config(path: Path) -> bool:
    name = path.name.lower()
    return name in CONFIG_NAMES or name.startswith(".markdownlintrc.")


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".json") or name == ".markdownlintrc":
        return "json"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


def _extract_line_length(line: str) -> int | None:
    match = re.search(
        r'["\']?line[_-]?length["\']?\s*:\s*(\d+)\b',
        line,
        re.IGNORECASE,
    )
    if match:
        return int(match.group(1))
    match = re.search(r"^\s*line-length\s*:\s*(\d+)\s*(?:#.*)?$", line, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


class MarkdownlintAnalyzer:
    """Audit markdownlint configuration for Markdown hygiene and security risks.

    Scans `.markdownlint.json`, `.markdownlintrc`, and package.json markdownlint
    blocks for disabled inline-HTML checks, wildcard rule suppressions, broad
    ignore patterns on security docs, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
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
        for path in sorted(self.root.rglob(".markdownlint*")):
            if path.is_file() and path not in found and _is_markdownlint_config(path):
                found.append(path)
        for path in sorted(self.root.rglob(".markdownlintrc*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and (
                    "markdownlint" in data or "markdownlintConfig" in data
                ):
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _record_rule_disable(
        self,
        rule: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[MarkdownlintFinding],
        info: MarkdownlintInfo,
    ) -> None:
        normalized = rule.upper()
        info.disabled_rules.append(normalized)

        if normalized in INLINE_HTML_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="inline_html_disabled",
                    severity="high",
                    message=f"{normalized} disabled — inline HTML in Markdown can enable XSS in rendered docs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in ALT_TEXT_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="alt_text_disabled",
                    severity="medium",
                    message=f"{normalized} disabled — missing alt text reduces accessibility and link safety",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in LINK_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="link_rule_disabled",
                    severity="medium",
                    message=f"{normalized} disabled — keep bare URL and link fragment checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in HEADING_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="heading_rule_disabled",
                    severity="low",
                    message=f"{normalized} disabled — heading hygiene helps catch malformed docs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in STRUCTURE_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="structure_rule_disabled",
                    severity="low",
                    message=f"{normalized} disabled — keep code block and table style checks enabled",
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
        findings: list[MarkdownlintFinding],
        info: MarkdownlintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if DEFAULT_FALSE_PATTERN.search(line):
            info.default_enabled = False
            findings.append(
                MarkdownlintFinding(
                    kind="default_disabled",
                    severity="high",
                    message="default=false disables all markdownlint rules — prefer explicit rule overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        default_true = re.search(
            r'["\']?default["\']?\s*:\s*(?:true|1|"on")',
            line,
            re.IGNORECASE,
        )
        if default_true:
            info.default_enabled = True

        wildcard = WILDCARD_RULE_DISABLE_PATTERN.search(line)
        if wildcard:
            findings.append(
                MarkdownlintFinding(
                    kind="wildcard_rule_disable",
                    severity="high",
                    message=f"wildcard rule disable {wildcard.group(1)!r} suppresses multiple checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        for match in RULE_DISABLE_PATTERN.finditer(line):
            self._record_rule_disable(
                match.group(1),
                lineno,
                rel,
                line,
                findings,
                info,
            )

        yaml_disable = RULE_DISABLE_YAML_PATTERN.match(line)
        if yaml_disable:
            self._record_rule_disable(
                yaml_disable.group(1),
                lineno,
                rel,
                line,
                findings,
                info,
            )

        line_length = _extract_line_length(line)
        if line_length is not None:
            info.line_length_max = line_length
            if line_length >= 200:
                findings.append(
                    MarkdownlintFinding(
                        kind="line_length_high",
                        severity="medium",
                        message=f"line-length={line_length} is very high — keep Markdown readable and reviewable",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if re.search(r'["\']?ignores?["\']?\s*:', line, re.IGNORECASE) or line.lower().startswith(
            "ignore:"
        ):
            info.has_ignore = True

        if IGNORE_SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="ignore_sensitive_path",
                    severity="high",
                    message="ignore skips security/compliance Markdown paths — lint policy docs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_WILDCARD_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="ignore_wildcard",
                    severity="medium",
                    message="wildcard ignore pattern may hide Markdown issues — scope ignores narrowly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in markdownlint config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in markdownlint config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in markdownlint config — avoid remote code execution",
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
            return findings, MarkdownlintInfo(path=rel)

        info = MarkdownlintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

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
  "MD013": {
    "line_length": 120,
    "code_blocks": false,
    "tables": false
  },
  "MD033": {
    "allowed_elements": []
  },
  "MD045": true,
  "MD034": true,
  "MD024": {
    "siblings_only": true
  },
  "MD041": true,
  "ignores": [
    "node_modules"
  ]
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "markdownlint configs: none found"
        return (
            f"markdownlint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "markdownlint config analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            default = (
                "default"
                if info.default_enabled is None
                else ("true" if info.default_enabled else "false")
            )
            length = info.line_length_max if info.line_length_max is not None else "default"
            lines.append(f"  - {info.path}: default={default}, line_length_max={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
