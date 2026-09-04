"""IsortAnalyzer — audit isort import-sorting configs for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pyproject.toml",
    ".isort.cfg",
    "setup.cfg",
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
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?|isort)\]",
    re.IGNORECASE,
)
SETUP_CFG_ISORT_SECTION = re.compile(r"^\[isort\]", re.IGNORECASE | re.MULTILINE)
TOX_ISORT_SECTION = re.compile(r"^\[isort\]", re.IGNORECASE | re.MULTILINE)
SKIP_SOURCE_PATTERN = re.compile(
    r"(?:skip|extend_skip|skip_glob|extend_skip_glob)\s*=\s*[^\n#]*\b(?:src|lib|app)\b",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"line_length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
LINE_LENGTH_LOW_PATTERN = re.compile(
    r"line_length\s*=\s*(?:[1-9]|[1-5][0-9])\b",
    re.IGNORECASE,
)
FORCE_SINGLE_LINE_PATTERN = re.compile(
    r"force_single_line\s*=\s*true\b",
    re.IGNORECASE,
)
HONOR_NOQA_FALSE_PATTERN = re.compile(
    r"honor_noqa\s*=\s*false\b",
    re.IGNORECASE,
)
FLOAT_TO_TOP_PATTERN = re.compile(
    r"float_to_top\s*=\s*true\b",
    re.IGNORECASE,
)
ATOMIC_FALSE_PATTERN = re.compile(
    r"atomic\s*=\s*false\b",
    re.IGNORECASE,
)
COMBINE_AS_IMPORTS_FALSE_PATTERN = re.compile(
    r"combine_as_imports\s*=\s*false\b",
    re.IGNORECASE,
)
INCLUDE_TRAILING_COMMA_FALSE_PATTERN = re.compile(
    r"include_trailing_comma\s*=\s*false\b",
    re.IGNORECASE,
)
USE_PARENTHESES_FALSE_PATTERN = re.compile(
    r"use_parentheses\s*=\s*false\b",
    re.IGNORECASE,
)
SKIP_GITIGNORE_TRUE_PATTERN = re.compile(
    r"skip_gitignore\s*=\s*true\b",
    re.IGNORECASE,
)
SRC_PATHS_SOURCE_PATTERN = re.compile(
    r"src_paths\s*=\s*[^\n]*[\"'](?:tests|docs|examples)[\"']",
    re.IGNORECASE,
)
MISSING_BLACK_PROFILE_PATTERN = re.compile(
    r"profile\s*=\s*[\"'](?!black)[^\"']+[\"']",
    re.IGNORECASE,
)
SECTIONS_MISSING_CORE_PATTERN = re.compile(
    r"sections\s*=\s*\[[^\]]*\]",
    re.IGNORECASE,
)


@dataclass
class IsortFinding:
    """A security or best-practice issue in an isort configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class IsortInfo:
    """Parsed metadata about an isort configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    line_length: int | None = None
    profile: str | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class IsortStats:
    """Aggregate isort analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name in (".isort.cfg", "setup.cfg", "tox.ini"):
        return "ini"
    return "unknown"


def _extract_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_string_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*[\"']([^\"']+)[\"']",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1)


def _extract_list_values(line: str, key: str) -> list[str]:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*\[(.*?)\]\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return []
    return re.findall(r'["\']([^"\']+)["\']', match.group(1))


class IsortAnalyzer:
    """Audit isort configuration for import hygiene and security risks.

    Scans pyproject.toml [tool.isort], .isort.cfg, setup.cfg [isort], and
    tox.ini [isort] for skip patterns that exclude source trees, disabled
    noqa handling, hardcoded secrets, and formatting settings that conflict with
    Black or reduce import safety.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[IsortFinding] | None = None
        self._stats: IsortStats | None = None
        self._infos: list[IsortInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return isort configuration paths found in the project."""
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
                if "[tool.isort" not in text and "[tool:isort" not in text:
                    continue
            elif name == "setup.cfg":
                if not SETUP_CFG_ISORT_SECTION.search(text):
                    continue
            elif name == "tox.ini":
                if not TOX_ISORT_SECTION.search(text):
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[IsortFinding],
        info: IsortInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = ISORT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_int_value(stripped, "line_length")
        if line_length is not None:
            info.line_length = line_length

        profile = _extract_string_value(stripped, "profile")
        if profile is not None:
            info.profile = profile

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in isort config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in isort config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in isort config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_SOURCE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_source",
                    severity="medium",
                    message="skip/extend_skip excludes source directories — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_HIGH_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="line_length_high",
                    severity="medium",
                    message="line_length > 200 reduces readability — align with Black (88)",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_LOW_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="line_length_low",
                    severity="low",
                    message="line_length < 60 causes excessive wrapping — consider 88",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_SINGLE_LINE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="force_single_line",
                    severity="medium",
                    message="force_single_line=true hurts readability and reviewability",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HONOR_NOQA_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="honor_noqa_false",
                    severity="high",
                    message="honor_noqa=false ignores noqa comments — keep noqa respected",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FLOAT_TO_TOP_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="float_to_top",
                    severity="low",
                    message="float_to_top=true mixes import styles — prefer consistent grouping",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ATOMIC_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="atomic_false",
                    severity="low",
                    message="atomic=false may leave partial import rewrites on failure",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COMBINE_AS_IMPORTS_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="combine_as_imports_false",
                    severity="low",
                    message="combine_as_imports=false increases import noise — enable combining",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INCLUDE_TRAILING_COMMA_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="include_trailing_comma_false",
                    severity="low",
                    message="include_trailing_comma=false conflicts with Black profile — enable trailing commas",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if USE_PARENTHESES_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="use_parentheses_false",
                    severity="low",
                    message="use_parentheses=false conflicts with Black profile — enable parentheses",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_GITIGNORE_TRUE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_gitignore_true",
                    severity="medium",
                    message="skip_gitignore=true may sort imports in gitignored sensitive files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SRC_PATHS_SOURCE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="src_paths_misconfigured",
                    severity="medium",
                    message="src_paths omits application packages — verify first-party detection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MISSING_BLACK_PROFILE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="non_black_profile",
                    severity="low",
                    message="non-black isort profile may conflict with Black formatting — use profile=black",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        sections_match = SECTIONS_MISSING_CORE_PATTERN.search(line)
        if sections_match:
            values = _extract_list_values(stripped, "sections")
            lowered = {value.upper() for value in values}
            if values and not {"FUTURE", "STDLIB"}.issubset(lowered):
                findings.append(
                    IsortFinding(
                        kind="sections_missing_core",
                        severity="medium",
                        message="custom sections omit FUTURE or STDLIB — keep core import groups",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[IsortFinding], IsortInfo]:
        findings: list[IsortFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, IsortInfo(path=rel, file_kind=_file_kind(path))

        info = IsortInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_isort_section = path.name in (".isort.cfg",)

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if ISORT_SECTION_PATTERN.match(line.strip()):
                in_isort_section = True
            elif line.strip().startswith("[") and not ISORT_SECTION_PATTERN.match(line.strip()):
                in_isort_section = False
            if not in_isort_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[IsortFinding]:
        """Scan isort configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[IsortFinding] = []
        infos: list[IsortInfo] = []
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
        self._stats = IsortStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> IsortStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[IsortInfo]:
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
        """Scaffold a hardened isort configuration template."""
        return """\
# Generated by DevAI IsortAnalyzer
[tool.isort]
profile = "black"
line_length = 88
combine_as_imports = true
include_trailing_comma = true
use_parentheses = true
honor_noqa = true
atomic = true
skip_gitignore = false
known_first_party = ["my_package"]
src_paths = ["src", "tests"]
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "isort configs: none found"
        return (
            f"isort configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "isort analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            length = info.line_length if info.line_length is not None else "default"
            profile = info.profile if info.profile is not None else "default"
            lines.append(f"  - {info.path}: line_length={length}, profile={profile}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
