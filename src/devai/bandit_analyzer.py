"""BanditAnalyzer — audit Bandit Python security scanner configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

BANDIT_CONFIG_NAMES = (
    ".bandit",
    "bandit.yaml",
    "bandit.yml",
    ".bandit.yaml",
    ".bandit.yml",
)
BANDIT_SECTION_MARKERS = ("[tool.bandit]", "[bandit]")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|xox[baprs]-)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
BROAD_EXCLUDE_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:\*\*?|/\*\*?|\*\*/\*|/\*\*/\*|/|\.)\s*(?:#.*)?$",
)
WILDCARD_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:[\"']?\*[\"']?|B\*|all)\s*(?:#.*)?$",
    re.IGNORECASE,
)
SKIP_SECURITY_TEST_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B(?:10[1-9]|20[0-9]|30[0-9]|40[0-9]|50[0-9]|60[0-9]|70[0-9])\s*(?:#.*)?$",
    re.IGNORECASE,
)
DISABLED_ASSERT_CHECK_PATTERN = re.compile(
    r"^\s*skips\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
BROAD_ASSERT_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:\*\*?|\*|/\*\*?)\s*(?:#.*)?$",
)
BASELINE_IGNORE_ALL_PATTERN = re.compile(
    r"^\s*(?:baseline|ignore-nosec)\s*:\s*(?:true|yes)\s*$",
    re.IGNORECASE,
)
NOSEC_BYPASS_PATTERN = re.compile(
    r"(?:#\s*nosec\s*$|nosec\s*:\s*true|ignore-nosec\s*:\s*true)",
    re.IGNORECASE,
)
LOW_CONFIDENCE_PATTERN = re.compile(
    r"^\s*confidence\s*[:=]\s*(?:LOW|low)\s*$",
    re.IGNORECASE,
)
RUN_ALL_TESTS_OFF_PATTERN = re.compile(
    r"^\s*tests\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
INLINE_API_KEY_PATTERN = re.compile(
    r"(?:BANDIT_API_KEY|bandit[_-]?api[_-]?key)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
SHELL_INJECTION_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B60[0-7]\s*(?:#.*)?$",
    re.IGNORECASE,
)
SQL_INJECTION_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B608\s*(?:#.*)?$",
    re.IGNORECASE,
)
HARDCODED_PASSWORD_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B10[56]\s*(?:#.*)?$",
    re.IGNORECASE,
)
EVAL_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B307\s*(?:#.*)?$",
    re.IGNORECASE,
)
PICKLE_SKIP_PATTERN = re.compile(
    r"^\s*(?:-\s*)?B301\s*(?:#.*)?$",
    re.IGNORECASE,
)


@dataclass
class BanditFinding:
    """A security or best-practice issue in a Bandit config."""

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
class BanditInfo:
    """Parsed metadata about a Bandit config file."""

    path: str
    skip_count: int = 0
    exclude_count: int = 0
    has_profiles: bool = False
    lines: int = 0


@dataclass
class BanditStats:
    """Aggregate Bandit analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bandit_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in BANDIT_CONFIG_NAMES:
        return True
    if lower in ("pyproject.toml", "setup.cfg") and path.is_file():
        return True
    return False


def _file_has_bandit_section(path: Path) -> bool:
    if path.name.lower() not in ("pyproject.toml", "setup.cfg"):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(marker in text for marker in BANDIT_SECTION_MARKERS)


class BanditAnalyzer:
    """Audit Bandit configs for hardcoded tokens, broad skips, and weakened security checks.

    Scans `.bandit`, `bandit.yaml`, and `[tool.bandit]` / `[bandit]` sections for embedded
    credentials, wildcard path exclusions, disabled security tests, and nosec bypasses.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[BanditFinding] | None = None
        self._stats: BanditStats | None = None
        self._infos: list[BanditInfo] | None = None

    def files(self) -> list[Path]:
        """Return Bandit config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_bandit_file(path) and _file_has_bandit_section(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[BanditFinding], BanditInfo]:
        findings: list[BanditFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BanditInfo(path=rel)

        info = BanditInfo(path=rel, lines=len(raw_lines))
        in_skips_block = False
        in_exclude_block = False
        in_assert_used_block = False
        in_assert_skips_block = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^\s*assert_used\s*:", line, re.IGNORECASE):
                in_assert_used_block = True
                in_assert_skips_block = False
                in_skips_block = False
                in_exclude_block = False
            elif re.search(r"^\s*(?:skips|skip)\s*:", line, re.IGNORECASE):
                if in_assert_used_block:
                    in_assert_skips_block = True
                    in_skips_block = False
                else:
                    in_skips_block = True
                in_exclude_block = False
            elif re.search(r"^\s*(?:exclude_dirs|exclude)\s*:", line, re.IGNORECASE):
                in_exclude_block = True
                in_skips_block = False
                in_assert_skips_block = False
            elif re.search(r"^\s*profiles\s*:", line, re.IGNORECASE):
                info.has_profiles = True
            elif re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                if in_assert_used_block and not re.match(r"^\s{2,}", line):
                    in_assert_used_block = False
                    in_assert_skips_block = False
                if in_skips_block:
                    in_skips_block = False
                if in_exclude_block:
                    in_exclude_block = False

            if in_skips_block and re.match(r"^\s*-\s*", line):
                info.skip_count += 1
                if WILDCARD_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="wildcard_skip",
                            severity="high",
                            message="wildcard skip disables all Bandit checks — remove blanket skips",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif SHELL_INJECTION_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="shell_injection_skip",
                            severity="high",
                            message="shell injection test skipped — do not disable B601-B608 without documented reason",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif SQL_INJECTION_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="sql_injection_skip",
                            severity="high",
                            message="SQL injection test B608 skipped — harden queries instead of disabling",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif HARDCODED_PASSWORD_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="hardcoded_password_skip",
                            severity="medium",
                            message="hardcoded password test skipped — use secrets management instead of B105/B106 skip",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif EVAL_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="eval_skip",
                            severity="medium",
                            message="eval/exec test B307 skipped — remove eval() usage instead of disabling",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif PICKLE_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="pickle_skip",
                            severity="medium",
                            message="pickle deserialization test B301 skipped — use safe serialization formats",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif SKIP_SECURITY_TEST_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="security_test_skip",
                            severity="medium",
                            message="security test skipped — document why and scope skips to specific files",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_exclude_block and re.match(r"^\s*-\s*", line):
                info.exclude_count += 1
                if BROAD_EXCLUDE_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="broad_exclude",
                            severity="high",
                            message="wildcard exclude_dirs hides code from Bandit — scope exclusions to specific paths",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_assert_skips_block and re.match(r"^\s*-\s*", line):
                if BROAD_ASSERT_SKIP_PATTERN.match(stripped):
                    findings.append(
                        BanditFinding(
                            kind="broad_assert_skip",
                            severity="medium",
                            message="broad assert_used skip disables assert checks project-wide",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Bandit config — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_API_KEY_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="api_key",
                        severity="high",
                        message="inline Bandit API key — use environment variables for credentials",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_ASSERT_CHECK_PATTERN.search(line) and in_assert_used_block:
                findings.append(
                    BanditFinding(
                        kind="disabled_assert_check",
                        severity="medium",
                        message="assert_used checks disabled — keep assert scanning enabled in production code",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BASELINE_IGNORE_ALL_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="baseline_bypass",
                        severity="medium",
                        message="baseline or ignore-nosec bypass enabled — review suppressed findings regularly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if NOSEC_BYPASS_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="nosec_bypass",
                        severity="medium",
                        message="nosec bypass in config — avoid blanket # nosec suppression in Bandit settings",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOW_CONFIDENCE_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="low_confidence",
                        severity="low",
                        message="low confidence threshold — use MEDIUM or HIGH for security scanning",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if RUN_ALL_TESTS_OFF_PATTERN.search(line):
                findings.append(
                    BanditFinding(
                        kind="empty_tests",
                        severity="high",
                        message="empty tests list disables Bandit scanning — include security test IDs or remove config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[BanditFinding]:
        """Scan Bandit config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BanditFinding] = []
        infos: list[BanditInfo] = []
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
        self._stats = BanditStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BanditStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BanditInfo]:
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
        """Scaffold a hardened Bandit config template."""
        return """\
# Bandit config — https://bandit.readthedocs.io/
# Run: bandit -r src/ -c bandit.yaml
exclude_dirs:
  - /tests/fixtures/
  - /.venv/
skips: []
# assert_used:
#   skips:
#     - '**/test_*.py'
#     - '**/tests/**'
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bandit: none found"
        return (
            f"Bandit: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bandit config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: skips={info.skip_count}, "
                f"excludes={info.exclude_count}, profiles={info.has_profiles}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
