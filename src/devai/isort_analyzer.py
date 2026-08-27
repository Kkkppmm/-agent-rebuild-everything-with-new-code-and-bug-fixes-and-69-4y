"""IsortAnalyzer — audit isort configs for skip patterns, honor_noqa=false, and Black profile conflicts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pyproject.toml",
    ".isort.cfg",
    "setup.cfg",
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
    r"(?:^|\s|,)(?:skip|skip_glob)\s*=\s*[^\n]*(?:^|\s|,|\"|')"
    r"(?:src|lib|app)(?:/|\"|,|\s|$)",
    re.IGNORECASE,
)
SKIP_GLOB_BROAD_PATTERN = re.compile(
    r"skip_glob\s*=\s*\[[^\]]*[\"']\*\*?/?\*[\"']",
    re.IGNORECASE,
)
PROFILE_NOT_BLACK_PATTERN = re.compile(
    r"profile\s*=\s*[\"']?(?!black\b)[a-z0-9_-]+[\"']?",
    re.IGNORECASE,
)
FORCE_SINGLE_LINE_PATTERN = re.compile(
    r"force[_-]?single[_-]?line\s*=\s*true\b",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"line[_-]?length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
ISORT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]isort(?:\.[^\]]+)?|settings|isort)\]",
    re.IGNORECASE,
)
BLACK_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]black(?:\.[^\]]+)?)\]",
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
    profile: str | None = None
    line_length: int | None = None
    honor_noqa: bool | None = None
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
    if path.name.endswith(".cfg"):
        return "ini"
    return "unknown"


def _extract_toml_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_toml_string_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*[\"']([^\"']+)[\"']\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*([a-zA-Z0-9_-]+)\s*$",
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


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in ("true", "yes", "1", "on"):
        return True
    if lowered in ("false", "no", "0", "off"):
        return False
    return None


class IsortAnalyzer:
    """Audit isort configuration for skip patterns, honor_noqa=false, and Black profile conflicts.

    Scans pyproject.toml [tool.isort], .isort.cfg, and setup.cfg [isort] for broad skip
    patterns, disabled noqa handling, line-length mismatches with Black, and hardcoded secrets.
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
                if "[isort]" not in text.lower():
                    continue
            found.append(path)
        return found

    def _read_black_line_length(self, path: Path) -> int | None:
        if path.name != "pyproject.toml":
            return None
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        in_black = False
        for raw in raw_lines:
            line = raw.strip()
            if BLACK_SECTION_PATTERN.match(line):
                in_black = True
            elif line.startswith("[") and not BLACK_SECTION_PATTERN.match(line):
                in_black = False
            if not in_black:
                continue
            length = _extract_toml_int_value(line, "line-length")
            if length is not None:
                return length
        return None

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[IsortFinding],
        info: IsortInfo,
        black_line_length: int | None,
        has_black_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        section_match = ISORT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_toml_int_value(stripped, "line_length")
        if line_length is None:
            ini_length = _extract_ini_value(stripped, "line_length")
            if ini_length and ini_length.isdigit():
                line_length = int(ini_length)
        if line_length is not None:
            info.line_length = line_length

        profile = _extract_toml_string_value(stripped, "profile")
        if profile is None:
            profile = _extract_ini_value(stripped, "profile")
        if profile is not None:
            info.profile = profile

        honor_noqa = _extract_toml_string_value(stripped, "honor_noqa")
        if honor_noqa is None:
            honor_noqa = _extract_ini_value(stripped, "honor_noqa")
        parsed_honor = _parse_bool(honor_noqa)
        if parsed_honor is not None:
            info.honor_noqa = parsed_honor

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
                    message="honor_noqa=false ignores noqa directives — keep noqa handling enabled",
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

        if SKIP_GLOB_BROAD_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="skip_glob_broad",
                    severity="high",
                    message="skip_glob uses overly broad wildcard — imports may be unchecked",
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
                    message="force_single_line=true hurts readability — prefer multi-line imports",
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

        if has_black_section and PROFILE_NOT_BLACK_PATTERN.search(line):
            findings.append(
                IsortFinding(
                    kind="black_profile_conflict",
                    severity="medium",
                    message="profile is not black while [tool.black] exists — use profile=black for consistency",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if info.profile == "black" and info.line_length is not None:
            expected = black_line_length if black_line_length is not None else 88
            if info.line_length != expected:
                findings.append(
                    IsortFinding(
                        kind="black_line_length_mismatch",
                        severity="medium",
                        message=(
                            f"isort line_length={info.line_length} mismatches Black "
                            f"line-length={expected} — align formatter settings"
                        ),
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
        black_line_length = self._read_black_line_length(path)
        has_black_section = False
        if path.name == "pyproject.toml":
            has_black_section = any(
                BLACK_SECTION_PATTERN.match(line.strip()) for line in raw_lines
            )

        in_isort_section = path.name in (".isort.cfg", "setup.cfg")
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
                if line.strip().lower().startswith("[isort]"):
                    in_isort_section = True
                elif line.strip().startswith("[") and not line.strip().lower().startswith("[isort]"):
                    in_isort_section = False
                if not in_isort_section:
                    continue
            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                black_line_length,
                has_black_section,
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
force_single_line = false
known_first_party = ["myapp"]
skip_glob = ["*/migrations/*", "*/.venv/*"]
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
            honor = info.honor_noqa if info.honor_noqa is not None else "default"
            lines.append(
                f"  - {info.path}: profile={profile}, line_length={length}, honor_noqa={honor}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
