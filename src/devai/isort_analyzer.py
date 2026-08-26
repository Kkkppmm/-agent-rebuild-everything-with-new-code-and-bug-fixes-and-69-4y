"""IsortAnalyzer — audit isort configs for import-sorting hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".isort.cfg",
    "setup.cfg",
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
HONOR_NOQA_FALSE_PATTERN = re.compile(r"honor_noqa\s*=\s*false\b", re.IGNORECASE)
SKIP_SOURCE_PATTERN = re.compile(
    r"(?:skip|extend_skip)\s*=\s*[^\n#]*\b(?:src|lib|app|package)\b",
    re.IGNORECASE,
)
SKIP_GLOB_BROAD_PATTERN = re.compile(
    r"(?:skip_glob|extend_skip_glob)\s*=\s*[^\n#]*\*\*",
    re.IGNORECASE,
)
SKIP_ALL_PATTERN = re.compile(
    r"(?:skip|extend_skip)\s*=\s*\[[^\]]*[\"']\*[\"']",
    re.IGNORECASE,
)
FORCE_SINGLE_LINE_PATTERN = re.compile(r"force_single_line\s*=\s*true\b", re.IGNORECASE)
FILTER_FILES_FALSE_PATTERN = re.compile(r"filter_files\s*=\s*false\b", re.IGNORECASE)
KNOWN_THIRD_PARTY_ALL_PATTERN = re.compile(
    r"known_third_party\s*=\s*\[[^\]]*[\"']\*[\"']",
    re.IGNORECASE,
)
FORCE_SORT_WITHIN_SECTIONS_FALSE_PATTERN = re.compile(
    r"force_sort_within_sections\s*=\s*false\b",
    re.IGNORECASE,
)
LINES_AFTER_IMPORTS_HIGH_PATTERN = re.compile(
    r"lines_after_imports\s*=\s*(?:[6-9]|[1-9][0-9]+)\b",
    re.IGNORECASE,
)
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
SETUP_CFG_ISORT_SECTION = re.compile(r"^\[isort\]", re.IGNORECASE | re.MULTILINE)


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
    if name == ".isort.cfg":
        return "ini"
    if name == "setup.cfg":
        return "ini"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


def _extract_profile(line: str) -> str | None:
    match = re.search(
        r'^profile\s*=\s*["\']([^"\']+)["\']',
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.search(
        r"^profile\s*=\s*(\S+)",
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return match.group(1).strip("\"'")
    return None


class IsortAnalyzer:
    """Audit isort configuration for import-sorting hygiene and security risks.

    Scans .isort.cfg, setup.cfg [isort], and pyproject.toml [tool.isort] for
    broad skip patterns, honor_noqa=false, Black profile conflicts, hardcoded
    secrets, and overly permissive known_third_party settings.
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
            if name == "pyproject.toml":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "[tool.isort" not in text and "[tool:isort" not in text:
                    continue
            if name == "setup.cfg":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not SETUP_CFG_ISORT_SECTION.search(text):
                    continue
            found.append(path)
        return found

    def _has_black_config(self) -> bool:
        pyproject = self.root / "pyproject.toml"
        if not pyproject.is_file():
            return False
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "[tool.black" in text or "[tool:black" in text

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[IsortFinding],
        info: IsortInfo,
        has_black: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = ISORT_SECTION_PATTERN.match(stripped) or SETUP_CFG_ISORT_SECTION.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        profile = _extract_profile(stripped)
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

        if HONOR_NOQA_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="honor_noqa_false",
                    severity="high",
                    message="honor_noqa=false ignores noqa comments — keep noqa respected for import overrides",
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
                    message="skip includes source directories — narrow skip patterns to build artifacts only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_GLOB_BROAD_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_glob_broad",
                    severity="medium",
                    message="skip_glob uses ** wildcard — may skip production source files from import sorting",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_ALL_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_all",
                    severity="high",
                    message="skip=* disables import sorting for all files — remove wildcard skip",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if has_black and profile is not None and profile.lower() != "black":
            findings.append(
                IsortFinding(
                    kind="black_profile_conflict",
                    severity="medium",
                    message="isort profile is not 'black' but Black formatter is configured — use profile=black for compatibility",
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
                    message="force_single_line=true conflicts with Black formatting — disable for Black projects",
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
                    message="filter_files=false processes all files including vendored code — enable filtering",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if KNOWN_THIRD_PARTY_ALL_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="known_third_party_all",
                    severity="medium",
                    message="known_third_party=* treats every package as third-party — list explicit packages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_SORT_WITHIN_SECTIONS_FALSE_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="force_sort_within_sections_false",
                    severity="low",
                    message="force_sort_within_sections=false allows inconsistent import ordering within sections",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINES_AFTER_IMPORTS_HIGH_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="lines_after_imports_high",
                    severity="low",
                    message="lines_after_imports > 5 adds excessive blank lines after imports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_isort_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == ".isort.cfg":
            return True
        if path.name == "setup.cfg":
            if SETUP_CFG_ISORT_SECTION.match(line.strip()):
                return True
            if line.strip().startswith("[") and not SETUP_CFG_ISORT_SECTION.match(line.strip()):
                return False
            return in_section
        if path.name == "pyproject.toml":
            if ISORT_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not ISORT_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        return True

    def _analyze_file(
        self,
        path: Path,
        has_black: bool,
    ) -> tuple[list[IsortFinding], IsortInfo]:
        findings: list[IsortFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, IsortInfo(path=rel, file_kind=_file_kind(path))

        info = IsortInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_isort_section = path.name == ".isort.cfg"
        profile_set = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in ("setup.cfg", "pyproject.toml"):
                in_isort_section = self._in_isort_section(line, in_isort_section, path)
                if not in_isort_section:
                    continue
            profile = _extract_profile(line.strip())
            if profile is not None:
                profile_set = True
            self._scan_line(line, lineno, rel, findings, info, has_black)

        if has_black and not profile_set and in_isort_section:
            findings.append(
                IsortFinding(
                    kind="black_profile_conflict",
                    severity="medium",
                    message="Black formatter is configured but isort profile is missing — set profile=black",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[IsortFinding]:
        """Scan isort configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[IsortFinding] = []
        infos: list[IsortInfo] = []
        paths = self.config_files()
        has_black = self._has_black_config()

        for path in paths:
            file_findings, info = self._analyze_file(path, has_black)
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
force_sort_within_sections = true
known_third_party = []
skip_glob = [
    ".venv/*",
    "build/*",
    "dist/*",
]
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
            profile = info.profile if info.profile is not None else "default"
            lines.append(f"  - {info.path}: profile={profile}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
