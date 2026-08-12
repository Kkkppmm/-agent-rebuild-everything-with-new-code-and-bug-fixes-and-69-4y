"""SemgrepAnalyzer — audit Semgrep rule configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SEMGREP_CONFIG_NAMES = (
    ".semgrep.yml",
    ".semgrep.yaml",
    "semgrep.yml",
    "semgrep.yaml",
)
SEMGREP_CONFIG_DIRS = (".semgrep", "semgrep")
SEMGREP_RULE_DIRS = ("rules",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|sgp_[A-Za-z0-9]{20,}|semgrep_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|endpoint|registry|api|server)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
DISABLED_RULE_PATTERN = re.compile(
    r"^\s*(?:status|enabled)\s*:\s*(?:disable|disabled|false)\s*$",
    re.IGNORECASE,
)
DANGEROUS_FLAG_PATTERN = re.compile(
    r"(?:--dangerous|--allow-untrusted-autofix|--no-git-ignore|--disable-version-check)",
    re.IGNORECASE,
)
BROAD_EXCLUDE_PATTERN = re.compile(
    r"^\s*-\s*(?:\*\*?|/\*\*?|\*\*/\*|/\*\*/\*)\s*(?:#.*)?$",
)
CATCH_ALL_PATTERN = re.compile(
    r"^\s*pattern\s*:\s*(?:\.\.\.|\$[A-Z_]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
SEVERITY_DOWNGRADE_PATTERN = re.compile(
    r"^\s*severity\s*:\s*(?:INFO|WARNING)\s*$",
    re.IGNORECASE,
)
SKIP_VALIDATION_PATTERN = re.compile(
    r"(?:validate\s*:\s*false|nosemgrep\s*:\s*true|skip-nested\s*:\s*true)",
    re.IGNORECASE,
)
AUTOFIX_UNSAFE_PATTERN = re.compile(
    r"^\s*(?:autofix|fix)\s*:\s*(?:true|yes)\s*$",
    re.IGNORECASE,
)
EXCLUDE_ALL_RULES_PATTERN = re.compile(
    r"^\s*(?:rules|include)\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
INLINE_APP_TOKEN_PATTERN = re.compile(
    r"(?:SEMGREP_APP_TOKEN|semgrep[_-]?app[_-]?token|app[_-]?token)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
WILDCARD_PATTERN_NOT_PATTERN = re.compile(
    r"^\s*pattern-not\s*:\s*(?:\.\.\.|\*|\$[A-Z_]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
LOW_CONFIDENCE_ONLY_PATTERN = re.compile(
    r"^\s*confidence\s*:\s*(?:LOW|low)\s*$",
)


@dataclass
class SemgrepFinding:
    """A security or best-practice issue in a Semgrep config."""

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
class SemgrepInfo:
    """Parsed metadata about a Semgrep config file."""

    path: str
    rule_count: int = 0
    exclude_entries: int = 0
    has_paths_config: bool = False
    lines: int = 0


@dataclass
class SemgrepStats:
    """Aggregate Semgrep analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_semgrep_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in SEMGREP_CONFIG_NAMES:
        return True
    parent_lower = path.parent.name.lower()
    if parent_lower in SEMGREP_CONFIG_DIRS and lower in (
        "settings.yml",
        "settings.yaml",
        "config.yml",
        "config.yaml",
        ".semgrep.yml",
        ".semgrep.yaml",
    ):
        return True
    if parent_lower in SEMGREP_RULE_DIRS and path.parent.parent.name.lower() in SEMGREP_CONFIG_DIRS:
        if lower.endswith((".yml", ".yaml")):
            return True
    return False


class SemgrepAnalyzer:
    """Audit Semgrep rule configs for hardcoded tokens, disabled rules, and weak defaults.

    Scans `.semgrep.yml`, `.semgrep/rules/`, and related configs for embedded credentials,
    wildcard path exclusions, disabled rules, catch-all patterns, and dangerous CLI flags.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[SemgrepFinding] | None = None
        self._stats: SemgrepStats | None = None
        self._infos: list[SemgrepInfo] | None = None

    def files(self) -> list[Path]:
        """Return Semgrep config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_semgrep_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[SemgrepFinding], SemgrepInfo]:
        findings: list[SemgrepFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SemgrepInfo(path=rel)

        info = SemgrepInfo(path=rel, lines=len(raw_lines))
        in_exclude_block = False
        rule_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^\s*(?:paths|exclude)\s*:", line, re.IGNORECASE):
                in_exclude_block = True
                info.has_paths_config = True
            elif in_exclude_block and re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                in_exclude_block = False

            if in_exclude_block and re.match(r"^\s*-\s*", line):
                info.exclude_entries += 1
                if BROAD_EXCLUDE_PATTERN.match(stripped):
                    findings.append(
                        SemgrepFinding(
                            kind="broad_exclude",
                            severity="high",
                            message="wildcard path exclude hides code from Semgrep — scope exclusions to specific paths",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if re.match(r"^\s*-\s*id\s*:", line, re.IGNORECASE):
                rule_count += 1

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Semgrep config — use SEMGREP_APP_TOKEN env var or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_APP_TOKEN_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="app_token",
                        severity="high",
                        message="inline Semgrep App token — use SEMGREP_APP_TOKEN environment variable",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP URL in Semgrep config — use HTTPS for Semgrep Cloud and registry endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_RULE_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="disabled_rule",
                        severity="medium",
                        message="rule disabled in config — remove disabled rules or document why security checks are off",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_FLAG_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="dangerous_flag",
                        severity="high",
                        message="dangerous Semgrep CLI flag — avoid --dangerous and --allow-untrusted-autofix in CI",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CATCH_ALL_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="catch_all_pattern",
                        severity="medium",
                        message="catch-all pattern matches everything — tighten rule patterns to reduce false positives",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SEVERITY_DOWNGRADE_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="severity_downgrade",
                        severity="low",
                        message="low severity on custom rule — use ERROR for security-critical findings",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_VALIDATION_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="skip_validation",
                        severity="medium",
                        message="validation or nosemgrep bypass enabled — do not disable Semgrep rule validation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AUTOFIX_UNSAFE_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="unsafe_autofix",
                        severity="medium",
                        message="autofix enabled on rule — review autofix changes carefully before merging",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EXCLUDE_ALL_RULES_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="empty_rules",
                        severity="high",
                        message="empty rules list disables Semgrep scanning — include rules or remove config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_PATTERN_NOT_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="wildcard_pattern_not",
                        severity="medium",
                        message="broad pattern-not excludes all matches — scope negations to specific patterns",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOW_CONFIDENCE_ONLY_PATTERN.search(line):
                findings.append(
                    SemgrepFinding(
                        kind="low_confidence",
                        severity="low",
                        message="low-confidence rule — prefer MEDIUM or HIGH confidence for security rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        info.rule_count = rule_count
        return findings, info

    def analyze(self) -> list[SemgrepFinding]:
        """Scan Semgrep config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SemgrepFinding] = []
        infos: list[SemgrepInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = SemgrepStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SemgrepStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SemgrepInfo]:
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Semgrep config template."""
        return """\
# Semgrep config — https://semgrep.dev/docs/
# Use SEMGREP_APP_TOKEN env var for Semgrep Cloud — never commit tokens
rules:
  - id: example-insecure-eval
    pattern: eval(...)
    message: Avoid eval() — use safer alternatives
    languages: [python]
    severity: ERROR
    metadata:
      category: security
# paths:
#   exclude:
#     - tests/fixtures/
#     - vendor/
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Semgrep: none found"
        return (
            f"Semgrep: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Semgrep config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: rules={info.rule_count}, "
                f"excludes={info.exclude_entries}, paths={info.has_paths_config}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
