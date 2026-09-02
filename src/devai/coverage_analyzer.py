"""CoverageAnalyzer — audit coverage.py configs for test-coverage hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".coveragerc",
    "setup.cfg",
    "pyproject.toml",
    "tox.ini",
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
FAIL_UNDER_ZERO_PATTERN = re.compile(
    r"fail_under\s*=\s*0\b",
    re.IGNORECASE,
)
FAIL_UNDER_LOW_PATTERN = re.compile(
    r"fail_under\s*=\s*([1-9]|[1-4][0-9])\b",
    re.IGNORECASE,
)
OMIT_SOURCE_PATTERN = re.compile(
    r"omit\s*=\s*[^\n]*\b(?:src|lib|app|package)\b",
    re.IGNORECASE,
)
INSECURE_DATA_FILE_PATTERN = re.compile(
    r"(?:data_file|data_suffix|data_suffix|note)\s*=\s*[\"']?(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
SKIP_COVERED_PATTERN = re.compile(
    r"skip_covered\s*=\s*true\b",
    re.IGNORECASE,
)
SHOW_MISSING_FALSE_PATTERN = re.compile(
    r"show_missing\s*=\s*false\b",
    re.IGNORECASE,
)
EXCLUDE_LINES_BROAD_PATTERN = re.compile(
    r"exclude_lines\s*=\s*[^\n]*(?:pragma:\s*no\s*cover|def\s+__repr__|raise\s+NotImplementedError|\bpass\b)",
    re.IGNORECASE,
)
EXCLUDE_LINE_ENTRY_PATTERN = re.compile(
    r"^\s*(?:pragma:\s*no\s*cover|def\s+__repr__|raise\s+NotImplementedError|\bpass\b)\s*$",
    re.IGNORECASE,
)
PRECISION_ZERO_PATTERN = re.compile(
    r"precision\s*=\s*0\b",
    re.IGNORECASE,
)
PLUGIN_UNTRUSTED_PATTERN = re.compile(
    r"(?:plugins?\s*=|plugin\s*=).*(?:\.\./|/etc/|/tmp/|\.ssh/)",
    re.IGNORECASE,
)
DISABLE_WARNINGS_PATTERN = re.compile(
    r"disable_warnings\s*=\s*[^\n#]+",
    re.IGNORECASE,
)
BRANCH_DISABLED_PATTERN = re.compile(
    r"branch\s*=\s*false\b",
    re.IGNORECASE,
)
RELATIVE_FILES_FALSE_PATTERN = re.compile(
    r"relative_files\s*=\s*false\b",
    re.IGNORECASE,
)
COVERAGE_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]coverage(?:\.[^\]]+)?|coverage(?::[^\]]+)?)\]",
    re.IGNORECASE,
)
SETUP_CFG_COVERAGE_SECTION = re.compile(
    r"^\[coverage(?::[^\]]+)?\]",
    re.IGNORECASE | re.MULTILINE,
)
TOX_COVERAGE_SECTION = re.compile(
    r"^\[coverage\]",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class CoverageFinding:
    """A security or best-practice issue in a coverage.py configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CoverageInfo:
    """Parsed metadata about a coverage.py configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    fail_under: int | None = None
    branch: bool | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class CoverageStats:
    """Aggregate coverage.py analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == ".coveragerc":
        return "ini"
    if name in ("setup.cfg", "tox.ini"):
        return "ini"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class CoverageAnalyzer:
    """Audit coverage.py configuration for coverage hygiene and security risks.

    Scans .coveragerc, setup.cfg [coverage:*], pyproject.toml [tool.coverage.*],
    and tox.ini [coverage] for low fail_under thresholds, broad omit patterns,
    skip_covered, disabled show_missing, untrusted plugins, and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CoverageFinding] | None = None
        self._stats: CoverageStats | None = None
        self._infos: list[CoverageInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return coverage.py configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if not path.is_file():
                continue
            if name == "pyproject.toml":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "[tool.coverage" not in text and "[tool:coverage" not in text:
                    continue
            if name == "setup.cfg":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not SETUP_CFG_COVERAGE_SECTION.search(text):
                    continue
            if name == "tox.ini":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not TOX_COVERAGE_SECTION.search(text):
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CoverageFinding],
        info: CoverageInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = (
            COVERAGE_SECTION_PATTERN.match(stripped)
            or SETUP_CFG_COVERAGE_SECTION.match(stripped)
            or TOX_COVERAGE_SECTION.match(stripped)
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in coverage config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in coverage config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in coverage config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FAIL_UNDER_ZERO_PATTERN.search(line):
            info.fail_under = 0
            findings.append(
                CoverageFinding(
                    kind="fail_under_zero",
                    severity="high",
                    message="fail_under=0 disables coverage enforcement — set a meaningful threshold",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        fail_low = FAIL_UNDER_LOW_PATTERN.search(line)
        if fail_low:
            info.fail_under = int(fail_low.group(1))
            findings.append(
                CoverageFinding(
                    kind="fail_under_low",
                    severity="medium",
                    message="fail_under below 50% allows low test coverage — raise the threshold",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        fail_match = re.search(r"fail_under\s*=\s*(\d+)\b", stripped, re.IGNORECASE)
        if fail_match and info.fail_under is None:
            info.fail_under = int(fail_match.group(1))

        if OMIT_SOURCE_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="omit_source",
                    severity="high",
                    message="omit skips source directories from coverage — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_DATA_FILE_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="insecure_data_file",
                    severity="high",
                    message="data_file points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_COVERED_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="skip_covered",
                    severity="medium",
                    message="skip_covered=true hides uncovered lines from reports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHOW_MISSING_FALSE_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="show_missing_false",
                    severity="medium",
                    message="show_missing=false hides uncovered line numbers in reports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_LINES_BROAD_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="exclude_lines_broad",
                    severity="medium",
                    message="exclude_lines uses broad patterns that can hide untested code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_LINE_ENTRY_PATTERN.search(stripped):
            findings.append(
                CoverageFinding(
                    kind="exclude_lines_broad",
                    severity="medium",
                    message="exclude_lines uses broad patterns that can hide untested code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PRECISION_ZERO_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="precision_zero",
                    severity="low",
                    message="precision=0 rounds coverage percentages — use at least 1",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PLUGIN_UNTRUSTED_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="plugin_untrusted",
                    severity="high",
                    message="coverage plugin loaded from untrusted path — use project-local plugins only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_WARNINGS_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="disable_warnings",
                    severity="low",
                    message="disable_warnings suppresses coverage diagnostics — remove broad disables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BRANCH_DISABLED_PATTERN.search(line):
            info.branch = False
            findings.append(
                CoverageFinding(
                    kind="branch_disabled",
                    severity="low",
                    message="branch=false disables branch coverage — enable for thorough testing",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"branch\s*=\s*true\b", stripped, re.IGNORECASE):
            info.branch = True

        if RELATIVE_FILES_FALSE_PATTERN.search(line):
            findings.append(
                CoverageFinding(
                    kind="relative_files_false",
                    severity="low",
                    message="relative_files=false can break coverage in CI — prefer true for portability",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_coverage_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == ".coveragerc":
            return True
        if path.name == "setup.cfg":
            if SETUP_CFG_COVERAGE_SECTION.match(line.strip()):
                return True
            if line.strip().startswith("[") and not SETUP_CFG_COVERAGE_SECTION.match(line.strip()):
                return False
            return in_section
        if path.name == "pyproject.toml":
            if COVERAGE_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not COVERAGE_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        if path.name == "tox.ini":
            if TOX_COVERAGE_SECTION.match(line.strip()):
                return True
            if line.strip().startswith("[") and not TOX_COVERAGE_SECTION.match(line.strip()):
                return False
            return in_section
        return True

    def _analyze_file(self, path: Path) -> tuple[list[CoverageFinding], CoverageInfo]:
        findings: list[CoverageFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CoverageInfo(path=rel, file_kind=_file_kind(path))

        info = CoverageInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_coverage_section = path.name == ".coveragerc"
        has_source = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in ("setup.cfg", "pyproject.toml", "tox.ini"):
                in_coverage_section = self._in_coverage_section(line, in_coverage_section, path)
                if not in_coverage_section:
                    continue
            if re.search(r"^\s*source\s*=", line, re.IGNORECASE):
                has_source = True
            self._scan_line(line, lineno, rel, findings, info)

        if not has_source and path.name in (".coveragerc", "setup.cfg", "pyproject.toml"):
            findings.append(
                CoverageFinding(
                    kind="source_omitted",
                    severity="medium",
                    message="no source= configured — coverage may miss project packages",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[CoverageFinding]:
        """Scan coverage.py configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CoverageFinding] = []
        infos: list[CoverageInfo] = []
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
        self._stats = CoverageStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CoverageStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CoverageInfo]:
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
        """Scaffold a hardened coverage.py configuration template."""
        return """\
# Generated by DevAI CoverageAnalyzer
[tool.coverage.run]
source = ["src"]
branch = true
relative_files = true
omit = [
    "*/tests/*",
    "*/__pycache__/*",
]

[tool.coverage.report]
fail_under = 80
show_missing = true
skip_covered = false
precision = 1
exclude_lines = [
    "pragma: no cover",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
]

[tool.coverage.html]
directory = "htmlcov"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Coverage configs: none found"
        return (
            f"Coverage configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Coverage analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            fail_under = info.fail_under if info.fail_under is not None else "default"
            branch = "enabled" if info.branch else ("disabled" if info.branch is False else "default")
            lines.append(f"  - {info.path}: fail_under={fail_under}, branch={branch}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
