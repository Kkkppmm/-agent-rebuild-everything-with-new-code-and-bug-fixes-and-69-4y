"""IsortAnalyzer — audit isort configs for skip patterns, honor_noqa=false, and Black profile conflicts."""

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
HONOR_NOQA_FALSE_PATTERN = re.compile(
    r"honor[_-]?noqa\s*=\s*(?:false|no|0)\b",
    re.IGNORECASE,
)
SKIP_SOURCE_PATTERN = re.compile(
    r"(?:skip|skip_glob)\s*=\s*[^\n]*(?:^|\s|,)(?:src|lib|app)(?:/|\s|,|$)",
    re.IGNORECASE,
)
PROFILE_BLACK_PATTERN = re.compile(
    r"profile\s*=\s*[\"']?black[\"']?\b",
    re.IGNORECASE,
)
LINE_LENGTH_CONFLICT_PATTERN = re.compile(
    r"line_length\s*=\s*(?:[1-7][0-9]|[89][0-7]|[1-9][0-9]{2,})\b",
    re.IGNORECASE,
)
FORCE_SORT_WITHIN_SECTIONS_FALSE_PATTERN = re.compile(
    r"force_sort_within_sections\s*=\s*(?:false|no|0)\b",
    re.IGNORECASE,
)
COMBINE_AS_IMPORTS_FALSE_PATTERN = re.compile(
    r"combine_as_imports\s*=\s*(?:false|no|0)\b",
    re.IGNORECASE,
)
KNOWN_THIRD_PARTY_EMPTY_PATTERN = re.compile(
    r"known_third_party\s*=\s*\[\s*\]",
    re.IGNORECASE,
)
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?|isort|testenv:.*isort)\]",
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
    sections: list[str] = field(default_factory=list)
    profile: str = ""
    line_length: int | None = None


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
    if name in (".isort.cfg", "setup.cfg", "tox.ini"):
        return "ini"
    if name == "pyproject.toml":
        return "toml"
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


class IsortAnalyzer:
    """Audit isort configuration for import hygiene and Black compatibility risks.

    Scans .isort.cfg, setup.cfg [isort], pyproject.toml [tool.isort], and tox.ini
    for honor_noqa=false, skip patterns on source dirs, Black profile conflicts,
    hardcoded secrets, and empty known_third_party lists.
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
            if name == "tox.ini":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "isort" not in text.lower():
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

        section_match = ISORT_SECTION_PATTERN.match(stripped) or SETUP_CFG_ISORT_SECTION.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        profile_match = PROFILE_BLACK_PATTERN.search(line)
        if profile_match:
            info.profile = "black"

        line_length = _extract_int_value(stripped, "line_length") or _extract_int_value(
            stripped, "line-length"
        )
        if line_length is not None:
            info.line_length = line_length

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
                    severity="medium",
                    message="honor_noqa=false ignores noqa directives — respect inline suppressions",
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
                    message="skip/skip_glob excludes source directories — narrow skip patterns",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if info.profile == "black" and LINE_LENGTH_CONFLICT_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="black_profile_conflict",
                    severity="medium",
                    message="profile=black with non-88 line_length — align with Black defaults",
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
                    message="force_sort_within_sections=false reduces import consistency",
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
                    message="combine_as_imports=false splits related as-import lines",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if KNOWN_THIRD_PARTY_EMPTY_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="known_third_party_empty",
                    severity="low",
                    message="known_third_party=[] provides no third-party hints — declare dependencies",
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
        in_isort_section = path.name not in ("pyproject.toml", "setup.cfg", "tox.ini")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                if ISORT_SECTION_PATTERN.match(line.strip()):
                    in_isort_section = True
                elif line.strip().startswith("[") and not ISORT_SECTION_PATTERN.match(line.strip()):
                    in_isort_section = False
                if not in_isort_section:
                    continue
            elif path.name == "setup.cfg":
                if SETUP_CFG_ISORT_SECTION.match(line.strip()):
                    in_isort_section = True
                elif line.strip().startswith("[") and not SETUP_CFG_ISORT_SECTION.match(line.strip()):
                    in_isort_section = False
                if not in_isort_section:
                    continue
            elif path.name == "tox.ini":
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
honor_noqa = true
force_sort_within_sections = true
combine_as_imports = true
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
