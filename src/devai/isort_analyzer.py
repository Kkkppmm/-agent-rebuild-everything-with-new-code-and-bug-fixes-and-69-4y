"""IsortAnalyzer — audit isort configs for import hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".isort.cfg",
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
HONOR_NOQA_FALSE_PATTERN = re.compile(r"honor_noqa\s*=\s*false\b", re.IGNORECASE)
SKIP_SOURCE_PATTERN = re.compile(
    r"(?:skip|extend_skip)\s*=\s*(?:[^\n]*[\"'](?:src|lib|app)[\"']|(?:src|lib|app)\b)",
    re.IGNORECASE,
)
SKIP_GLOB_BROAD_PATTERN = re.compile(
    r"skip_glob\s*=\s*\[[^\]]*[\"']\*\*\/\*[\"']",
    re.IGNORECASE,
)
SKIP_GLOB_SOURCE_PATTERN = re.compile(
    r"skip_glob\s*=\s*\[[^\]]*[\"'](?:\*\/)?(?:src|lib|app)(?:\/\*)?[\"']",
    re.IGNORECASE,
)
NO_SECTIONS_PATTERN = re.compile(r"no_sections\s*=\s*true\b", re.IGNORECASE)
FILTER_FILES_FALSE_PATTERN = re.compile(r"filter_files\s*=\s*false\b", re.IGNORECASE)
FORCE_SINGLE_LINE_PATTERN = re.compile(r"force_single_line\s*=\s*true\b", re.IGNORECASE)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"line_length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
PROFILE_BLACK_PATTERN = re.compile(r"profile\s*=\s*[\"']?black[\"']?", re.IGNORECASE)
PROFILE_BLACK_LINE_LENGTH_PATTERN = re.compile(
    r"line_length\s*=\s*(?!88\b)\d+\b",
    re.IGNORECASE,
)
KNOWN_WILDCARD_PATTERN = re.compile(
    r"known_(?:first|third|local)_party\s*=\s*\[[^\]]*[\"']\*(?:\/\*)?[\"']",
    re.IGNORECASE,
)
SKIP_INIT_PY_FALSE_PATTERN = re.compile(r"skip_init_py\s*=\s*false\b", re.IGNORECASE)
COMBINE_AS_IMPORTS_FALSE_PATTERN = re.compile(
    r"combine_as_imports\s*=\s*false\b",
    re.IGNORECASE,
)
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?|isort)\]",
    re.IGNORECASE,
)
SETUP_CFG_ISORT_PATTERN = re.compile(r"^\[isort\]", re.IGNORECASE)


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
    profile: str = ""
    line_length: int | None = None
    skip_modules: list[str] = field(default_factory=list)
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
    if name.endswith(".toml"):
        return "toml"
    if name.endswith(".cfg") or name == "tox.ini":
        return "ini"
    return "unknown"


def _extract_toml_list_values(line: str, key: str) -> list[str]:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*\[(.*?)\]\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return []
    return re.findall(r'["\']([^"\']+)["\']', match.group(1))


def _extract_toml_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_ini_list_values(line: str, key: str) -> list[str]:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(.+)$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return []
    value = match.group(1).strip()
    if value.startswith("[") and value.endswith("]"):
        return re.findall(r'["\']([^"\']+)["\']', value)
    return [part.strip().strip("\"'") for part in value.split(",") if part.strip()]


def _extract_ini_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_ini_string_value(line: str, key: str) -> str:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*[\"']?([^\"'\s#]+)[\"']?\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return ""
    return match.group(1)


class IsortAnalyzer:
    """Audit isort configuration for security and import hygiene risks.

    Scans .isort.cfg, setup.cfg [isort], pyproject.toml [tool.isort], and tox.ini
    for honor_noqa=false, broad skip/skip_glob patterns, Black profile conflicts,
    hardcoded secrets, and disabled file filtering.
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
                if "[isort]" not in text:
                    continue
            elif name == "tox.ini":
                if "[isort]" not in text:
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
        *,
        has_black_profile: bool,
    ) -> bool:
        """Scan a config line. Returns updated has_black_profile flag."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return has_black_profile

        section_match = ISORT_SECTION_PATTERN.match(stripped) or SETUP_CFG_ISORT_PATTERN.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_toml_int_value(stripped, "line_length")
        if line_length is None:
            line_length = _extract_ini_int_value(stripped, "line_length")
        if line_length is not None:
            info.line_length = line_length

        skip_modules = _extract_toml_list_values(stripped, "skip")
        if not skip_modules:
            skip_modules = _extract_ini_list_values(stripped, "skip")
        if skip_modules:
            info.skip_modules = skip_modules

        if PROFILE_BLACK_PATTERN.search(stripped):
            info.profile = "black"
            has_black_profile = True

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

        if HONOR_NOQA_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="honor_noqa_false",
                    severity="high",
                    message="honor_noqa=false ignores # noqa comments — keep noqa honored for security suppressions",
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
                    message="skip includes source directories — narrows import auditing coverage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_GLOB_BROAD_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_glob_broad",
                    severity="high",
                    message="skip_glob includes **/* — skips all files from import sorting",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_GLOB_SOURCE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_glob_source",
                    severity="medium",
                    message="skip_glob skips source directories — narrows import auditing coverage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_SECTIONS_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="no_sections",
                    severity="medium",
                    message="no_sections=true disables import grouping — harder to audit dependency structure",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FILTER_FILES_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="filter_files_false",
                    severity="medium",
                    message="filter_files=false processes non-Python files — may expose unintended paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_SINGLE_LINE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="force_single_line",
                    severity="low",
                    message="force_single_line=true reduces import readability in security reviews",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_HIGH_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="line_length_high",
                    severity="low",
                    message="line_length > 200 reduces readability — align with Black (88) when using profile=black",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if has_black_profile and PROFILE_BLACK_LINE_LENGTH_PATTERN.search(stripped):
            findings.append(
                IsortFinding(
                    kind="black_profile_conflict",
                    severity="medium",
                    message="profile=black with non-88 line_length conflicts with Black defaults — use line_length=88",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if KNOWN_WILDCARD_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="known_wildcard",
                    severity="medium",
                    message="known_*_party uses wildcard — may hide untrusted third-party imports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_INIT_PY_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_init_py_false",
                    severity="low",
                    message="skip_init_py=false may sort __init__.py unexpectedly — verify package boundaries",
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
                    message="combine_as_imports=false increases import line count — prefer true for reviewability",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return has_black_profile

    def _in_isort_section(self, path: Path, line: str, current: bool) -> bool:
        stripped = line.strip()
        if path.name == ".isort.cfg":
            return True
        if path.name == "pyproject.toml":
            if ISORT_SECTION_PATTERN.match(stripped):
                return True
            if stripped.startswith("[") and not ISORT_SECTION_PATTERN.match(stripped):
                return False
            return current
        if path.name in ("setup.cfg", "tox.ini"):
            if SETUP_CFG_ISORT_PATTERN.match(stripped):
                return True
            if stripped.startswith("[") and not SETUP_CFG_ISORT_PATTERN.match(stripped):
                return False
            return current
        return current

    def _analyze_file(self, path: Path) -> tuple[list[IsortFinding], IsortInfo]:
        findings: list[IsortFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, IsortInfo(path=rel, file_kind=_file_kind(path))

        info = IsortInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = path.name == ".isort.cfg"
        has_black_profile = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_section = self._in_isort_section(path, line, in_section)
            if not in_section:
                continue
            has_black_profile = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                has_black_profile=has_black_profile,
            )

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
honor_noqa = true
filter_files = true
combine_as_imports = true
force_sort_within_sections = true
skip_glob = []
known_third_party = []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Isort configs: none found"
        return (
            f"Isort configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Isort analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            profile = info.profile or "default"
            length = info.line_length if info.line_length is not None else "default"
            lines.append(f"  - {info.path}: profile={profile}, line_length={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
