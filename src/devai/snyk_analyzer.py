"""SnykAnalyzer — audit Snyk policy and CLI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SNYK_POLICY_NAMES = (".snyk",)
SNYK_CONFIG_NAMES = ("snyk.yaml", "snyk.yml", ".snyk.yaml", ".snyk.yml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:snyk_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|"
    r"ghp_|glpat-|AKIA|npm_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:api|endpoint|url|registry)\s*[:=]\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
IGNORE_BLOCK_PATTERN = re.compile(r"^\s*ignore\s*:", re.IGNORECASE)
PATCH_BLOCK_PATTERN = re.compile(r"^\s*patch\s*:", re.IGNORECASE)
EXCLUDE_BLOCK_PATTERN = re.compile(r"^\s*exclude\s*:", re.IGNORECASE)
IGNORE_ENTRY_PATTERN = re.compile(
    r"^\s*(?:SNYK-[A-Z0-9-]+|CVE-\d{4}-\d+|CWE-\d+|npm:[^\s:]+|pip:[^\s:]+)\s*:",
    re.IGNORECASE,
)
BROAD_IGNORE_PATH_PATTERN = re.compile(
    r"^\s*-\s*[\"']?(?:\*|\*\*|\.|\./\*|/\*\*?)[\"']?\s*:?\s*$",
    re.IGNORECASE,
)
WILDCARD_IGNORE_VALUE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?(?:\*|\*\*)[\"']?\s*:?\s*$",
    re.IGNORECASE,
)
EXPIRES_PATTERN = re.compile(r"^\s*expires\s*:", re.IGNORECASE)
REASON_PATTERN = re.compile(r"^\s*reason\s*:", re.IGNORECASE)
DISABLE_ALERTS_PATTERN = re.compile(
    r"^\s*(?:disableAlerts|disable-alerts|monitor)\s*:\s*(?:false|off|disabled)\s*$",
    re.IGNORECASE,
)
LOW_SEVERITY_THRESHOLD_PATTERN = re.compile(
    r"^\s*(?:severity-threshold|severityThreshold|fail-on)\s*:\s*[\"']?(?:low|none|info)[\"']?\s*$",
    re.IGNORECASE,
)
IGNORE_UNKNOWN_PATTERN = re.compile(
    r"^\s*(?:ignoreUnknown|ignore-unknown|skip-unresolved)\s*:\s*true\s*$",
    re.IGNORECASE,
)
ORG_TOKEN_PAIR_PATTERN = re.compile(
    r"(?:org|organization)[_-]?(?:id|slug)\s*[:=].*(?:token|api[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
TRUSTED_DOMAINS_HTTP_PATTERN = re.compile(
    r"^\s*(?:trustedDomains|trusted-domains)\s*:.*http://",
    re.IGNORECASE,
)
PATCH_DISABLED_PATTERN = re.compile(
    r"^\s*patch\s*:\s*(?:\{\}|null|none|false)\s*$",
    re.IGNORECASE,
)
EXCLUDE_GLOBAL_PATTERN = re.compile(r"^\s*global\s*:", re.IGNORECASE)


@dataclass
class SnykFinding:
    """A security or best-practice issue in a Snyk config."""

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
class SnykInfo:
    """Parsed metadata about a Snyk config file."""

    path: str
    config_type: str = "policy"
    ignore_entries: int = 0
    patch_entries: int = 0
    exclude_paths: int = 0
    has_expires: bool = False
    lines: int = 0


@dataclass
class SnykStats:
    """Aggregate Snyk analysis statistics."""

    configs: int
    files: int
    findings: int
    policy_files: int = 0
    cli_files: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_snyk_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in SNYK_POLICY_NAMES:
        return True
    return lower in SNYK_CONFIG_NAMES


def _config_type(path: Path) -> str:
    if path.name.lower() == ".snyk":
        return "policy"
    return "cli"


class SnykAnalyzer:
    """Audit Snyk policy and CLI configs for hardcoded tokens, broad ignores, and weak defaults.

    Scans `.snyk` policy files and `snyk.yaml` CLI configs for embedded credentials, wildcard
    vulnerability suppressions, missing ignore expiry dates, and lowered severity thresholds.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SnykFinding] | None = None
        self._stats: SnykStats | None = None
        self._infos: list[SnykInfo] | None = None

    def files(self) -> list[Path]:
        """Return Snyk config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_snyk_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[SnykFinding], SnykInfo]:
        findings: list[SnykFinding] = []
        rel = str(path.relative_to(self.root))
        config_type = _config_type(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SnykInfo(path=rel, config_type=config_type)

        info = SnykInfo(path=rel, config_type=config_type, lines=len(raw_lines))
        in_ignore = False
        in_ignore_entry = False
        ignore_entry_has_expires = False
        ignore_entry_has_reason = False
        ignore_entry_line = 0
        ignore_entry_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if IGNORE_BLOCK_PATTERN.match(line):
                in_ignore = True
                continue
            if PATCH_BLOCK_PATTERN.match(line):
                in_ignore = False
                info.patch_entries += 1
                if PATCH_DISABLED_PATTERN.match(line):
                    findings.append(
                        SnykFinding(
                            kind="patch_disabled",
                            severity="medium",
                            message="patch block empty — Snyk patches can mitigate issues without full upgrades",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue
            if EXCLUDE_BLOCK_PATTERN.match(line):
                in_ignore = False
                continue

            if IGNORE_ENTRY_PATTERN.match(line):
                if in_ignore_entry and not ignore_entry_has_expires:
                    findings.append(
                        SnykFinding(
                            kind="ignore_missing_expiry",
                            severity="medium",
                            message="ignore rule without expires date — set time-bound suppressions with documented reasons",
                            path=rel,
                            lineno=ignore_entry_line,
                            line="",
                        )
                    )
                if in_ignore_entry and not ignore_entry_has_reason:
                    findings.append(
                        SnykFinding(
                            kind="ignore_missing_reason",
                            severity="low",
                            message="ignore rule without reason — document why the vulnerability is accepted",
                            path=rel,
                            lineno=ignore_entry_line,
                            line="",
                        )
                    )
                in_ignore_entry = True
                ignore_entry_has_expires = False
                ignore_entry_has_reason = False
                ignore_entry_line = lineno
                ignore_entry_indent = indent
                info.ignore_entries += 1
                continue

            if in_ignore_entry and indent <= ignore_entry_indent and not IGNORE_ENTRY_PATTERN.match(line):
                if not ignore_entry_has_expires:
                    findings.append(
                        SnykFinding(
                            kind="ignore_missing_expiry",
                            severity="medium",
                            message="ignore rule without expires date — set time-bound suppressions with documented reasons",
                            path=rel,
                            lineno=ignore_entry_line,
                            line="",
                        )
                    )
                if not ignore_entry_has_reason:
                    findings.append(
                        SnykFinding(
                            kind="ignore_missing_reason",
                            severity="low",
                            message="ignore rule without reason — document why the vulnerability is accepted",
                            path=rel,
                            lineno=ignore_entry_line,
                            line="",
                        )
                    )
                in_ignore_entry = False

            if in_ignore_entry and EXPIRES_PATTERN.match(line):
                ignore_entry_has_expires = True
                info.has_expires = True

            if in_ignore_entry and REASON_PATTERN.match(line):
                ignore_entry_has_reason = True

            if in_ignore and (
                BROAD_IGNORE_PATH_PATTERN.match(line) or WILDCARD_IGNORE_VALUE_PATTERN.match(line)
            ):
                findings.append(
                    SnykFinding(
                        kind="broad_ignore",
                        severity="high",
                        message="wildcard ignore path — suppress specific CVEs/paths instead of '*' or '**'",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EXCLUDE_GLOBAL_PATTERN.match(line):
                info.exclude_paths += 1

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    SnykFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Snyk config — use SNYK_TOKEN env var or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) or TRUSTED_DOMAINS_HTTP_PATTERN.search(line):
                findings.append(
                    SnykFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP endpoint in Snyk config — use HTTPS for API and registry URLs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DISABLE_ALERTS_PATTERN.match(line):
                findings.append(
                    SnykFinding(
                        kind="alerts_disabled",
                        severity="high",
                        message="Snyk monitoring/alerts disabled — keep vulnerability monitoring enabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LOW_SEVERITY_THRESHOLD_PATTERN.match(line):
                findings.append(
                    SnykFinding(
                        kind="low_severity_threshold",
                        severity="medium",
                        message="severity threshold set to low/none — fail builds on high/critical findings",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if IGNORE_UNKNOWN_PATTERN.match(line):
                findings.append(
                    SnykFinding(
                        kind="ignore_unknown",
                        severity="medium",
                        message="ignoreUnknown enabled — unresolved vulnerabilities should be tracked, not skipped",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ORG_TOKEN_PAIR_PATTERN.search(line):
                findings.append(
                    SnykFinding(
                        kind="org_token_in_config",
                        severity="high",
                        message="organization id and token in same config file — store tokens in CI secrets only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if in_ignore_entry and not ignore_entry_has_expires:
            findings.append(
                SnykFinding(
                    kind="ignore_missing_expiry",
                    severity="medium",
                    message="ignore rule without expires date — set time-bound suppressions with documented reasons",
                    path=rel,
                    lineno=ignore_entry_line,
                    line="",
                )
            )

        if raw_lines and info.ignore_entries > 5 and not info.has_expires:
            findings.append(
                SnykFinding(
                    kind="many_ignores_no_expiry",
                    severity="medium",
                    message=f"{info.ignore_entries} ignore rules with no expiry dates — review suppressions regularly",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and config_type == "policy" and info.ignore_entries == 0 and info.patch_entries == 0:
            findings.append(
                SnykFinding(
                    kind="empty_policy",
                    severity="low",
                    message="Snyk policy file has no ignore or patch rules — confirm monitoring is configured elsewhere",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[SnykFinding]:
        """Scan Snyk config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SnykFinding] = []
        infos: list[SnykInfo] = []
        paths = self.files()
        policy_files = 0
        cli_files = 0

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            if info.config_type == "policy":
                policy_files += 1
            else:
                cli_files += 1

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = SnykStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            policy_files=policy_files,
            cli_files=cli_files,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SnykStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SnykInfo]:
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
        """Scaffold a hardened Snyk policy template."""
        return """\
# Snyk (https://snyk.io) policy file, docs: https://docs.snyk.io/manage-risk/policies/the-.snyk-file
version: v1.25.0
ignore: {}
patch: {}
# Example time-bound ignore (replace SNYK-XXX with a real issue id):
# ignore:
#   SNYK-JS-EXAMPLE-1234567:
#     - path/to/file.js:
#         reason: Temporary accept — tracked in SEC-123, upgrade planned Q2
#         expires: 2026-06-30T00:00:00.000Z
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Snyk: none found"
        return (
            f"Snyk: {stats.configs} file(s) ({stats.policy_files} policy, {stats.cli_files} cli), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Snyk config analysis:",
            f"  configs: {stats.configs}",
            f"  policy files: {stats.policy_files}",
            f"  cli files: {stats.cli_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: type={info.config_type}, "
                f"ignores={info.ignore_entries}, patches={info.patch_entries}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
