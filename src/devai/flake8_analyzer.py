"""Flake8Analyzer — audit Flake8 configs for broad ignores, disabled S rules, and source exclusions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".flake8",
    "setup.cfg",
    "tox.ini",
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
IGNORE_ALL_PATTERN = re.compile(
    r"(?:ignore|extend-ignore)\s*=\s*[^\n]*\bALL\b",
    re.IGNORECASE,
)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r"(?:ignore|extend-ignore)\s*=\s*[^\n]*\bS\d{3}\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"(?:exclude|extend-exclude)\s*=\s*[^\n]*(?:^|[,\s])(?:src|lib|app)(?:/|[,\s]|$)",
    re.IGNORECASE,
)
MAX_LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"max-line-length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
PER_FILE_IGNORES_SENSITIVE_PATTERN = re.compile(
    r"per-file-ignores\s*=\s*[^\n]*(?:settings|config|secrets?|auth)\.py[^\n]*S\d{3}",
    re.IGNORECASE,
)
FLAKE8_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]flake8|flake8|testenv:flake8)\]",
    re.IGNORECASE,
)
SETUP_CFG_FLAKE8_SECTION = re.compile(r"^\[flake8\]", re.IGNORECASE)


@dataclass
class Flake8Finding:
    """A security or best-practice issue in a Flake8 configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class Flake8Info:
    """Parsed metadata about a Flake8 configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    max_line_length: int | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class Flake8Stats:
    """Aggregate Flake8 analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name in (".flake8", "setup.cfg", "tox.ini"):
        return "ini"
    return "unknown"


def _extract_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*[=:]\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


class Flake8Analyzer:
    """Audit Flake8 configuration for security and linting hygiene risks.

    Scans .flake8, setup.cfg [flake8], tox.ini [testenv:flake8], and
    pyproject.toml [tool.flake8] for broad ignores, disabled bandit (S) rules,
    per-file security ignores on sensitive modules, and source exclusions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[Flake8Finding] | None = None
        self._stats: Flake8Stats | None = None
        self._infos: list[Flake8Info] | None = None

    def config_files(self) -> list[Path]:
        """Return Flake8 configuration paths found in the project."""
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
                if "[tool.flake8" not in text and "[tool:flake8" not in text:
                    continue
            elif name == "setup.cfg":
                if not SETUP_CFG_FLAKE8_SECTION.search(text):
                    continue
            elif name == "tox.ini":
                if "[testenv:flake8" not in text.lower():
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[Flake8Finding],
        info: Flake8Info,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = FLAKE8_SECTION_PATTERN.match(stripped) or SETUP_CFG_FLAKE8_SECTION.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_int_value(stripped, "max-line-length")
        if line_length is not None:
            info.max_line_length = line_length

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Flake8 config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Flake8 config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Flake8 config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ALL_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="ignore_all",
                    severity="high",
                    message="ignore=ALL disables all lint rules — remove broad ignores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="disabled_security_rules",
                    severity="high",
                    message="bandit (S) rules disabled — keep security lint rules enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PER_FILE_IGNORES_SENSITIVE_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="per_file_sensitive_ignore",
                    severity="high",
                    message="per-file-ignores relax security rules on sensitive modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from linting — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MAX_LINE_LENGTH_HIGH_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="max_line_length_high",
                    severity="medium",
                    message="max-line-length > 200 reduces readability — use 88-120",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_flake8_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == ".flake8":
            return True
        if path.name in ("setup.cfg", "tox.ini", "pyproject.toml"):
            if FLAKE8_SECTION_PATTERN.match(line.strip()) or SETUP_CFG_FLAKE8_SECTION.match(
                line.strip()
            ):
                return True
            if line.strip().startswith("[") and not (
                FLAKE8_SECTION_PATTERN.match(line.strip())
                or SETUP_CFG_FLAKE8_SECTION.match(line.strip())
            ):
                return False
            return in_section
        return True

    def _analyze_file(self, path: Path) -> tuple[list[Flake8Finding], Flake8Info]:
        findings: list[Flake8Finding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, Flake8Info(path=rel, file_kind=_file_kind(path))

        info = Flake8Info(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = path.name == ".flake8"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in (".flake8", "setup.cfg", "tox.ini", "pyproject.toml"):
                in_section = self._in_flake8_section(line, in_section, path)
                if not in_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[Flake8Finding]:
        """Scan Flake8 configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Flake8Finding] = []
        infos: list[Flake8Info] = []
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
        self._stats = Flake8Stats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> Flake8Stats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[Flake8Info]:
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
        """Scaffold a hardened Flake8 configuration template."""
        return """\
# Generated by DevAI Flake8Analyzer
[tool.flake8]
max-line-length = 88
extend-ignore = []
exclude = .git,__pycache__,.venv,build,dist
per-file-ignores =
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Flake8 configs: none found"
        return (
            f"Flake8 configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Flake8 analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            length = info.max_line_length if info.max_line_length is not None else "default"
            lines.append(f"  - {info.path}: max-line-length={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
