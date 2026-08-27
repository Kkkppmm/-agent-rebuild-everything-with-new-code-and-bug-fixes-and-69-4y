"""IsortAnalyzer — audit isort configs for skip patterns, honor_noqa=false, and Black profile conflicts."""

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
HONOR_NOQA_FALSE_PATTERN = re.compile(
    r"honor[_-]?noqa\s*=\s*false\b",
    re.IGNORECASE,
)
SKIP_SOURCE_PATTERN = re.compile(
    r"skip\s*=\s*(?:\[[^\]]*[\"'](?:src|lib|app)[\"']|[\"']?(?:src|lib|app)[\"']?\s*$)",
    re.IGNORECASE,
)
SKIP_GLOB_BROAD_PATTERN = re.compile(
    r"skip_glob\s*=\s*\[[^\]]*[\"']\*\*[\"']",
    re.IGNORECASE,
)
PROFILE_BLACK_PATTERN = re.compile(
    r"profile\s*=\s*[\"']?black[\"']?\b",
    re.IGNORECASE,
)
LINE_LENGTH_PATTERN = re.compile(
    r"line[_-]?length\s*=\s*(\d+)\b",
    re.IGNORECASE,
)
BLACK_SKIP_STRING_NORM_PATTERN = re.compile(
    r"skip-string-normalization\s*=\s*true\b",
    re.IGNORECASE,
)
BLACK_LINE_LENGTH_PATTERN = re.compile(
    r"line-length\s*=\s*(\d+)\b",
    re.IGNORECASE,
)
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?|isort|settings)\]",
    re.IGNORECASE,
)
GENERIC_SECTION_PATTERN = re.compile(r"^\[[^\]]+\]")


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
    line_length: int | None = None
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
    if path.name.endswith(".toml"):
        return "toml"
    if path.name.endswith(".cfg") or path.name.endswith(".ini"):
        return "ini"
    return "unknown"


def _extract_toml_string_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*[\"']([^\"']+)[\"']\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    return None


def _extract_ini_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(.+?)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    return value


def _extract_int_from_line(line: str, key: str) -> int | None:
    for extractor in (_extract_toml_string_value, _extract_ini_value):
        value = extractor(line, key)
        if value is not None and value.isdigit():
            return int(value)
    match = LINE_LENGTH_PATTERN.search(line)
    if match:
        return int(match.group(1))
    return None


class IsortAnalyzer:
    """Audit isort configuration for security and import-sorting hygiene risks.

    Scans pyproject.toml [tool.isort], .isort.cfg, setup.cfg, and tox.ini for
    honor_noqa=false, broad skip patterns, hardcoded secrets, and conflicts
    with Black when profile=black is enabled.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[IsortFinding] | None = None
        self._stats: IsortStats | None = None
        self._infos: list[IsortInfo] | None = None
        self._black_line_length: int | None = None
        self._black_skip_string_norm: bool = False
        self._has_black_section: bool = False

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
            elif name in ("setup.cfg", "tox.ini"):
                if "[isort]" not in text:
                    continue
            found.append(path)
        return found

    def _load_black_metadata(self) -> None:
        pyproject = self.root / "pyproject.toml"
        if not pyproject.is_file():
            return
        try:
            lines = pyproject.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return

        in_black = False
        for raw in lines:
            line = raw.strip()
            if re.match(r"^\[(?:tool[.:]black(?:\.[^\]]+)?)\]", line, re.IGNORECASE):
                in_black = True
                self._has_black_section = True
            elif line.startswith("[") and not re.match(
                r"^\[(?:tool[.:]black(?:\.[^\]]+)?)\]", line, re.IGNORECASE
            ):
                in_black = False
            if not in_black:
                continue
            if BLACK_SKIP_STRING_NORM_PATTERN.search(raw):
                self._black_skip_string_norm = True
            black_length = _extract_int_from_line(raw, "line-length")
            if black_length is not None:
                self._black_line_length = black_length

    def _in_isort_section(self, path: Path, line: str, in_section: bool) -> bool:
        stripped = line.strip()
        if path.name == ".isort.cfg":
            if stripped.startswith("#"):
                return True
            if ISORT_SECTION_PATTERN.match(stripped):
                return True
            return in_section or not stripped.startswith("[")
        if ISORT_SECTION_PATTERN.match(stripped):
            return True
        if stripped.startswith("[") and not ISORT_SECTION_PATTERN.match(stripped):
            return False
        return in_section

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[IsortFinding],
        info: IsortInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        section_match = ISORT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        profile = _extract_toml_string_value(stripped, "profile") or _extract_ini_value(
            stripped, "profile"
        )
        if profile:
            info.profile = profile

        line_length = _extract_int_from_line(stripped, "line_length")
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
                    severity="high",
                    message="honor_noqa=false ignores noqa suppressions — keep honor_noqa enabled",
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
                    message="skip excludes source directories from import sorting — narrow skip patterns",
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
                    message="skip_glob includes '**' — may skip most of the codebase from isort",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROFILE_BLACK_PATTERN.search(line):
            if not self._has_black_section:
                findings.append(
                    IsortFinding(
                        kind="black_profile_missing",
                        severity="medium",
                        message="profile=black but no [tool.black] section — add Black config or change profile",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if self._black_skip_string_norm:
                findings.append(
                    IsortFinding(
                        kind="black_profile_conflict",
                        severity="high",
                        message="profile=black conflicts with skip-string-normalization=true in Black config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _check_black_line_length_mismatch(
        self,
        info: IsortInfo,
        findings: list[IsortFinding],
    ) -> None:
        if (
            info.profile == "black"
            and info.line_length is not None
            and self._black_line_length is not None
            and info.line_length != self._black_line_length
        ):
            findings.append(
                IsortFinding(
                    kind="black_line_length_mismatch",
                    severity="medium",
                    message=(
                        f"line_length={info.line_length} differs from Black "
                        f"line-length={self._black_line_length} — align settings"
                    ),
                    path=info.path,
                    lineno=1,
                    line="",
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
        in_section = path.name == ".isort.cfg"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_section = self._in_isort_section(path, line, in_section)
            if not in_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        self._check_black_line_length_mismatch(info, findings)
        return findings, info

    def analyze(self) -> list[IsortFinding]:
        """Scan isort configs and return findings."""
        if self._findings is not None:
            return self._findings

        self._load_black_metadata()
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
skip_gitignore = true
known_first_party = ["my_package"]
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
            length = info.line_length if info.line_length is not None else "default"
            lines.append(f"  - {info.path}: profile={profile}, line_length={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
