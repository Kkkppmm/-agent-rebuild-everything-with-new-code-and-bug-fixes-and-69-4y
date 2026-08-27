"""Flake8Analyzer — audit Flake8 configs for lint hygiene and security risks."""

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
FLAKE8_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]flake8(?:\.[^\]]+)?|flake8)\]",
    re.IGNORECASE,
)
SETUP_CFG_FLAKE8_SECTION = re.compile(r"^\[flake8\]", re.IGNORECASE | re.MULTILINE)
TOX_FLAKE8_SECTION = re.compile(r"^\[flake8\]", re.IGNORECASE | re.MULTILINE)
IGNORE_ALL_PATTERN = re.compile(
    r"(?:ignore|extend-ignore)\s*=\s*[^\n#]*\b(?:E|F|W)\s*,\s*(?:E|F|W)\s*,\s*(?:E|F|W)\b",
    re.IGNORECASE,
)
IGNORE_EVERYTHING_PATTERN = re.compile(
    r"(?:ignore|extend-ignore)\s*=\s*[^\n#]*\bALL\b",
    re.IGNORECASE,
)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r"(?:ignore|extend-ignore)\s*=\s*[^\n#]*\bS(?:\d+)?\b",
    re.IGNORECASE,
)
SECURITY_RULE_IN_IGNORE_LINE_PATTERN = re.compile(
    r"\bS\d{3}\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"(?:exclude|extend-exclude)\s*=\s*[^\n#]*\b(?:src|lib|app)\b",
    re.IGNORECASE,
)
PER_FILE_SECURITY_IGNORE_PATTERN = re.compile(
    r"per-file-ignores\s*=\s*[^\n]*"
    r"(?:settings\.py|config\.py|secrets?\.py|auth\.py)[^\n]*\bS",
    re.IGNORECASE,
)
PER_FILE_LINE_SECURITY_IGNORE_PATTERN = re.compile(
    r"(?:settings\.py|config\.py|secrets?\.py|auth\.py)\s*:\s*[^\n]*\bS\d",
    re.IGNORECASE,
)
MAX_LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"max-line-length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
MAX_LINE_LENGTH_LOW_PATTERN = re.compile(
    r"max-line-length\s*=\s*(?:[1-9]|[1-5][0-9])\b",
    re.IGNORECASE,
)
EMPTY_SELECT_PATTERN = re.compile(
    r"select\s*=\s*(?:$|\s*$|\[\s*\])",
    re.IGNORECASE,
)
DOCSTRING_CONVENTION_DISABLED_PATTERN = re.compile(
    r"docstring-convention\s*=\s*(?:none|google|numpy|pep257)\b",
    re.IGNORECASE,
)


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
    ignore_rules: list[str] = field(default_factory=list)
    select_rules: list[str] = field(default_factory=list)
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
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_csv_codes(line: str, key: str) -> list[str]:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(.+?)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return []
    raw = match.group(1).split("#", 1)[0].strip()
    if raw.startswith("[") and raw.endswith("]"):
        return re.findall(r'["\']([^"\']+)["\']', raw)
    return [part.strip() for part in raw.split(",") if part.strip()]


class Flake8Analyzer:
    """Audit Flake8 configuration for lint hygiene and security risks.

    Scans .flake8, setup.cfg [flake8], tox.ini [flake8], and pyproject.toml
    [tool.flake8] for broad ignores, disabled bandit (S) rules, per-file
    security ignores, hardcoded secrets, and overly broad exclude patterns.
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
                if not TOX_FLAKE8_SECTION.search(text):
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

        section_match = FLAKE8_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        max_line_length = _extract_int_value(stripped, "max-line-length")
        if max_line_length is not None:
            info.max_line_length = max_line_length

        ignore_rules = _extract_csv_codes(stripped, "ignore")
        if ignore_rules:
            info.ignore_rules.extend(ignore_rules)

        extend_ignore = _extract_csv_codes(stripped, "extend-ignore")
        if extend_ignore:
            info.ignore_rules.extend(extend_ignore)

        select_rules = _extract_csv_codes(stripped, "select")
        if select_rules:
            info.select_rules.extend(select_rules)

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

        if IGNORE_EVERYTHING_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="ignore_all",
                    severity="high",
                    message="ignore=ALL disables all lint rules — remove blanket suppression",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif IGNORE_ALL_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="broad_ignore",
                    severity="medium",
                    message="broad ignore of E/F/W categories reduces lint coverage — narrow ignores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line) or (
            "ignore" in stripped.lower()
            and SECURITY_RULE_IN_IGNORE_LINE_PATTERN.search(stripped)
        ):
            findings.append(
                Flake8Finding(
                    kind="disabled_security_rule",
                    severity="high",
                    message="disabled bandit (S) rules in Flake8 config — keep security checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PER_FILE_SECURITY_IGNORE_PATTERN.search(line) or (
            PER_FILE_LINE_SECURITY_IGNORE_PATTERN.search(line)
        ):
            findings.append(
                Flake8Finding(
                    kind="per_file_security_ignore",
                    severity="high",
                    message="per-file-ignores suppress security rules on sensitive modules — avoid",
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
                    message="exclude/extend-exclude skips source directories — narrow exclusions",
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
                    message="max-line-length > 200 reduces readability — align with Black (88)",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MAX_LINE_LENGTH_LOW_PATTERN.search(line):
            findings.append(
                Flake8Finding(
                    kind="max_line_length_low",
                    severity="low",
                    message="max-line-length < 60 causes excessive wrapping — consider 88",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EMPTY_SELECT_PATTERN.search(line) and "select" in stripped.lower():
            findings.append(
                Flake8Finding(
                    kind="empty_select",
                    severity="medium",
                    message="empty select list disables explicit rule selection — configure select rules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOCSTRING_CONVENTION_DISABLED_PATTERN.search(line):
            match = re.search(
                r"docstring-convention\s*=\s*(none)\b",
                stripped,
                re.IGNORECASE,
            )
            if match:
                findings.append(
                    Flake8Finding(
                        kind="docstring_convention_none",
                        severity="low",
                        message="docstring-convention=none disables docstring linting — pick a convention",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[Flake8Finding], Flake8Info]:
        findings: list[Flake8Finding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, Flake8Info(path=rel, file_kind=_file_kind(path))

        info = Flake8Info(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_flake8_section = path.name == ".flake8"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if FLAKE8_SECTION_PATTERN.match(line.strip()):
                in_flake8_section = True
            elif line.strip().startswith("[") and not FLAKE8_SECTION_PATTERN.match(line.strip()):
                in_flake8_section = False
            if not in_flake8_section:
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
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude =
    .git,
    __pycache__,
    .venv,
    build,
    dist
per-file-ignores =
    tests/*: S101
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "flake8 configs: none found"
        return (
            f"flake8 configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "flake8 analysis:",
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
