"""MarkdownlintAnalyzer — audit markdownlint configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".markdownlint.json",
    ".markdownlint.yaml",
    ".markdownlint.yml",
    ".markdownlintrc",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DEFAULT_FALSE_PATTERN = re.compile(
    r"""["']?default["']?\s*:\s*false\b""",
    re.IGNORECASE,
)
RULE_DISABLED_PATTERN = re.compile(
    r"""["']?(MD\d{3})["']?\s*:\s*false\b""",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"""["']?line_length["']?\s*:\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b""",
    re.IGNORECASE,
)
LINE_LENGTH_LOW_PATTERN = re.compile(
    r"""["']?line_length["']?\s*:\s*(?:[1-9]|[1-3][0-9])\b""",
    re.IGNORECASE,
)
CUSTOM_RULES_PATTERN = re.compile(
    r"""["']?customRules["']?\s*:""",
    re.IGNORECASE,
)
IGNORE_FRONT_MATTER_PATTERN = re.compile(
    r"""["']?ignoreFrontMatter["']?\s*:\s*true\b""",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

# Security-sensitive markdownlint rules.
INLINE_HTML_RULES = frozenset({"MD033"})
LINK_RULES = frozenset({"MD045", "MD042", "MD051"})
HEADING_RULES = frozenset({"MD001", "MD002", "MD003", "MD041"})
LINE_LENGTH_RULES = frozenset({"MD013"})


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
    line_length: int | None = None
    has_custom_rules: bool = False
    ignore_front_matter: bool = False


@dataclass
class MarkdownlintStats:
    """Aggregate markdownlint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_markdownlint_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def _file_kind(path: Path) -> str:
    lower = path.name.lower()
    if lower.endswith(".json") or lower == ".markdownlintrc":
        return "json"
    if lower.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


class MarkdownlintAnalyzer:
    """Audit markdownlint configuration for markdown hygiene and security risks.

    Scans `.markdownlint.json`, `.markdownlint.yaml`, `.markdownlintrc`, and related
    configs for disabled security rules (MD033 inline HTML, MD045 alt text), default:
    false, permissive line lengths, customRules with remote URLs, and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MarkdownlintFinding] | None = None
        self._stats: MarkdownlintStats | None = None
        self._infos: list[MarkdownlintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return markdownlint configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_markdownlint_config(path):
                found.append(path)
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
        if rule not in info.disabled_rules:
            info.disabled_rules.append(rule)

        if rule in INLINE_HTML_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="inline_html_disabled",
                    severity="high",
                    message=f"{rule} disabled — inline HTML can enable XSS in rendered markdown",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif rule in LINK_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="link_rule_disabled",
                    severity="medium",
                    message=f"{rule} disabled — link and image hygiene checks are weakened",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif rule in HEADING_RULES:
            findings.append(
                MarkdownlintFinding(
                    kind="heading_rule_disabled",
                    severity="low",
                    message=f"{rule} disabled — heading structure checks are relaxed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        else:
            findings.append(
                MarkdownlintFinding(
                    kind="rule_disabled",
                    severity="medium",
                    message=f"{rule} disabled — markdownlint rule explicitly turned off",
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
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
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

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in markdownlint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MarkdownlintFinding(
                    kind="insecure_http",
                    severity="high",
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

        if DEFAULT_FALSE_PATTERN.search(line):
            info.default_enabled = False
            findings.append(
                MarkdownlintFinding(
                    kind="default_false",
                    severity="high",
                    message="default: false disables all markdownlint rules — enable default checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        rule_match = RULE_DISABLED_PATTERN.search(line)
        if rule_match:
            self._record_rule_disable(
                rule_match.group(1).upper(),
                lineno,
                rel,
                line,
                findings,
                info,
            )

        if LINE_LENGTH_HIGH_PATTERN.search(line):
            match = re.search(
                r"""["']?line_length["']?\s*:\s*(\d+)\b""",
                line,
                re.IGNORECASE,
            )
            if match:
                info.line_length = int(match.group(1))
            findings.append(
                MarkdownlintFinding(
                    kind="line_length_high",
                    severity="medium",
                    message="MD013 line_length is very high — long lines reduce reviewability",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_LOW_PATTERN.search(line):
            match = re.search(
                r"""["']?line_length["']?\s*:\s*(\d+)\b""",
                line,
                re.IGNORECASE,
            )
            if match:
                info.line_length = int(match.group(1))
            findings.append(
                MarkdownlintFinding(
                    kind="line_length_low",
                    severity="low",
                    message="MD013 line_length is very low — may cause noisy lint failures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CUSTOM_RULES_PATTERN.search(line):
            info.has_custom_rules = True
            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    MarkdownlintFinding(
                        kind="custom_rule_insecure_url",
                        severity="high",
                        message="customRules references insecure HTTP URL — audit third-party rule sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            else:
                findings.append(
                    MarkdownlintFinding(
                        kind="custom_rules_present",
                        severity="low",
                        message="customRules defined — review custom markdownlint rules for unsafe patterns",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if IGNORE_FRONT_MATTER_PATTERN.search(line):
            info.ignore_front_matter = True
            findings.append(
                MarkdownlintFinding(
                    kind="ignore_front_matter",
                    severity="low",
                    message="ignoreFrontMatter: true skips YAML front matter — metadata issues may be missed",
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

        info = MarkdownlintInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

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
// Generated by DevAI MarkdownlintAnalyzer
// markdownlint — https://github.com/DavidAnson/markdownlint
{
  "default": true,
  "MD013": {
    "line_length": 120,
    "code_blocks": false,
    "tables": false
  },
  "MD033": {
    "allowed_elements": []
  }
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
            "markdownlint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            default = "enabled" if info.default_enabled else "disabled"
            length = info.line_length if info.line_length is not None else "default"
            lines.append(
                f"  - {info.path}: default={default}, line_length={length}, "
                f"custom_rules={info.has_custom_rules}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
