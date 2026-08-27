"""BlackAnalyzer — audit Black formatter configs for formatting hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
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
SKIP_STRING_NORMALIZATION_PATTERN = re.compile(
    r"skip-string-normalization\s*=\s*true\b",
    re.IGNORECASE,
)
PREVIEW_PATTERN = re.compile(r"preview\s*=\s*true\b", re.IGNORECASE)
FAST_PATTERN = re.compile(r"fast\s*=\s*true\b", re.IGNORECASE)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"line-length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
LINE_LENGTH_LOW_PATTERN = re.compile(
    r"line-length\s*=\s*(?:[1-9]|[1-5][0-9])\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"(?:exclude|extend-exclude|force-exclude)\s*=\s*\[[^\]]*[\"'](?:src|lib|app)[\"']",
    re.IGNORECASE,
)
TARGET_VERSION_OLD_PATTERN = re.compile(
    r"target-version\s*=\s*\[[^\]]*[\"'](?:py2[67]|py3[0-6])[\"']",
    re.IGNORECASE,
)
UNSTABLE_FEATURE_PATTERN = re.compile(
    r"unstable\s*=\s*\[[^\]]*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
BLACK_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]black(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)


@dataclass
class BlackFinding:
    """A security or best-practice issue in a Black configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BlackInfo:
    """Parsed metadata about a Black configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    line_length: int | None = None
    target_versions: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


@dataclass
class BlackStats:
    """Aggregate Black analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.name.endswith(".toml"):
        return "toml"
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


class BlackAnalyzer:
    """Audit Black formatter configuration for security and formatting hygiene risks.

    Scans pyproject.toml [tool.black] sections for skip-string-normalization,
    preview/unstable features, broad exclude patterns, hardcoded secrets, and
    unsafe line-length or target-version settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BlackFinding] | None = None
        self._stats: BlackStats | None = None
        self._infos: list[BlackInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Black configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "[tool.black" not in text and "[tool:black" not in text:
                continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BlackFinding],
        info: BlackInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        section_match = BLACK_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_toml_int_value(stripped, "line-length")
        if line_length is not None:
            info.line_length = line_length

        target_versions = _extract_toml_list_values(stripped, "target-version")
        if target_versions:
            info.target_versions = target_versions

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Black config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Black config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Black config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_STRING_NORMALIZATION_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="skip_string_normalization",
                    severity="high",
                    message="skip-string-normalization=true allows homoglyph bypasses — keep normalization enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PREVIEW_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="preview",
                    severity="medium",
                    message="preview=true enables unstable formatting rules — pin stable Black versions in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FAST_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="fast",
                    severity="low",
                    message="fast=true may skip some formatting checks — prefer full formatting in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_HIGH_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="line_length_high",
                    severity="medium",
                    message="line-length > 200 reduces readability and reviewability — use 88-120",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LINE_LENGTH_LOW_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="line_length_low",
                    severity="low",
                    message="line-length < 60 causes excessive wrapping — consider 88",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from formatting — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TARGET_VERSION_OLD_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="target_version_old",
                    severity="medium",
                    message="target-version includes EOL Python — update to py310+",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSTABLE_FEATURE_PATTERN.search(line):
            findings.append(
                BlackFinding(
                    kind="unstable_features",
                    severity="medium",
                    message="unstable features enabled — may change formatting between Black releases",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[BlackFinding], BlackInfo]:
        findings: list[BlackFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BlackInfo(path=rel, file_kind=_file_kind(path))

        info = BlackInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_black_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if BLACK_SECTION_PATTERN.match(line.strip()):
                in_black_section = True
            elif line.strip().startswith("[") and not BLACK_SECTION_PATTERN.match(line.strip()):
                in_black_section = False
            if not in_black_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[BlackFinding]:
        """Scan Black configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BlackFinding] = []
        infos: list[BlackInfo] = []
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
        self._stats = BlackStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BlackStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BlackInfo]:
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
        """Scaffold a hardened Black configuration template."""
        return """\
# Generated by DevAI BlackAnalyzer
[tool.black]
line-length = 88
target-version = ["py310"]
preview = false
skip-string-normalization = false
extend-exclude = '''
/(
  \\.git
  | \\.venv
  | build
  | dist
)/
'''
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Black configs: none found"
        return (
            f"Black configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Black analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            length = info.line_length if info.line_length is not None else "default"
            targets = ", ".join(info.target_versions) if info.target_versions else "default"
            lines.append(f"  - {info.path}: line-length={length}, target-version={targets}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
