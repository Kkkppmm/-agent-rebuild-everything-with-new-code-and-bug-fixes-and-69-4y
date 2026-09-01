"""RuffAnalyzer — audit Ruff configuration for security and linting hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "ruff.toml",
    ".ruff.toml",
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
UNSAFE_FIXES_PATTERN = re.compile(r"unsafe-fixes\s*=\s*true\b", re.IGNORECASE)
IGNORE_ALL_PATTERN = re.compile(
    r"ignore\s*=\s*\[[^\]]*[\"']ALL[\"']",
    re.IGNORECASE,
)
EMPTY_SELECT_PATTERN = re.compile(r"select\s*=\s*\[\s*\]", re.IGNORECASE)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r"ignore\s*=\s*\[[^\]]*[\"']S(?:\d+)?[\"']",
    re.IGNORECASE,
)
PER_FILE_SECURITY_IGNORE_PATTERN = re.compile(
    r"(?:per-file-ignores|extend-per-file-ignores)\s*=\s*\{[^\}]*"
    r"(?:settings\.py|config\.py|secrets?\.py|auth\.py)[^\}]*[\"']S",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"exclude\s*=\s*\[[^\]]*[\"'](?:src|lib|app)[\"']",
    re.IGNORECASE,
)
FIXABLE_ALL_PATTERN = re.compile(
    r"fixable\s*=\s*\[[^\]]*[\"']ALL[\"']",
    re.IGNORECASE,
)
PREVIEW_UNSAFE_PATTERN = re.compile(
    r"preview\s*=\s*true\b.*unsafe-fixes\s*=\s*true\b|"
    r"unsafe-fixes\s*=\s*true\b.*preview\s*=\s*true\b",
    re.IGNORECASE,
)
BUILTINS_SHADOW_PATTERN = re.compile(
    r"builtins\s*=\s*\[[^\]]*[\"'](?:eval|exec|compile|open|input)[\"']",
    re.IGNORECASE,
)
ALLOWED_CONFUSABLES_PATTERN = re.compile(
    r"allowed-confusables\s*=\s*\[[^\]]*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
RUFF_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ruff(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
SECURITY_RULE_IN_IGNORE_LINE_PATTERN = re.compile(
    r'["\']S\d{3}["\']',
    re.IGNORECASE,
)


@dataclass
class RuffFinding:
    """A security or best-practice issue in a Ruff configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class RuffInfo:
    """Parsed metadata about a Ruff configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    select_rules: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


@dataclass
class RuffStats:
    """Aggregate Ruff analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name.endswith(".toml"):
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


class RuffAnalyzer:
    """Audit Ruff configuration for security and linting hygiene risks.

    Scans ruff.toml, .ruff.toml, and pyproject.toml [tool.ruff] sections for
    unsafe-fixes, ignore=ALL, disabled bandit (S) rules, per-file security
    ignores, hardcoded secrets, and overly broad exclude patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[RuffFinding] | None = None
        self._stats: RuffStats | None = None
        self._infos: list[RuffInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Ruff configuration paths found in the project."""
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
                if "[tool.ruff" not in text and "[tool:ruff" not in text:
                    continue
            found.append(path)
        return found

    def _in_ruff_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name != "pyproject.toml":
            return True
        if RUFF_SECTION_PATTERN.match(line.strip()):
            return True
        if line.strip().startswith("[") and not RUFF_SECTION_PATTERN.match(line.strip()):
            return False
        return in_section

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[RuffFinding],
        info: RuffInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        section_match = RUFF_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        select_rules = _extract_toml_list_values(stripped, "select")
        if select_rules:
            info.select_rules = select_rules

        ignore_rules = _extract_toml_list_values(stripped, "ignore")
        if ignore_rules:
            info.ignore_rules = ignore_rules

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Ruff config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Ruff config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Ruff config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_FIXES_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="unsafe_fixes",
                    severity="medium",
                    message="unsafe-fixes=true enables risky automatic fixes — review before CI auto-fix",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ALL_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="ignore_all",
                    severity="high",
                    message="ignore=[\"ALL\"] disables all lint rules — remove or narrow ignores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EMPTY_SELECT_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="empty_select",
                    severity="medium",
                    message="select=[] enables no lint rules — add explicit rule selections",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line) or (
            re.search(r"ignore\s*=", stripped, re.IGNORECASE)
            and SECURITY_RULE_IN_IGNORE_LINE_PATTERN.search(line)
        ):
            findings.append(
                RuffFinding(
                    kind="disabled_security_rules",
                    severity="high",
                    message="bandit (S) rules ignored — keep security lint rules enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PER_FILE_SECURITY_IGNORE_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="per_file_security_ignore",
                    severity="high",
                    message="per-file-ignores disable security rules on sensitive modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from linting — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FIXABLE_ALL_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="fixable_all",
                    severity="low",
                    message="fixable=[\"ALL\"] allows auto-fixing every rule — pair with safe review gates",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PREVIEW_UNSAFE_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="preview_unsafe",
                    severity="medium",
                    message="preview=true with unsafe-fixes=true — unstable rules with risky fixes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BUILTINS_SHADOW_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="builtins_shadow",
                    severity="medium",
                    message="builtins list shadows eval/exec — avoid masking dangerous builtins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOWED_CONFUSABLES_PATTERN.search(line):
            findings.append(
                RuffFinding(
                    kind="allowed_confusables",
                    severity="low",
                    message="allowed-confusables permits homoglyph bypasses — keep the list minimal",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[RuffFinding], RuffInfo]:
        findings: list[RuffFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, RuffInfo(path=rel, file_kind=_file_kind(path))

        info = RuffInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_ruff_section = path.name != "pyproject.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                if RUFF_SECTION_PATTERN.match(line.strip()):
                    in_ruff_section = True
                elif line.strip().startswith("[") and not RUFF_SECTION_PATTERN.match(line.strip()):
                    in_ruff_section = False
                if not in_ruff_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[RuffFinding]:
        """Scan Ruff configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[RuffFinding] = []
        infos: list[RuffInfo] = []
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
        self._stats = RuffStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> RuffStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[RuffInfo]:
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
        """Scaffold a hardened Ruff configuration template."""
        return """\
# Generated by DevAI RuffAnalyzer
[tool.ruff]
target-version = "py310"
line-length = 88
unsafe-fixes = false
preview = false

[tool.ruff.lint]
select = [
    "E", "F", "W",   # pycodestyle + pyflakes
    "I",             # isort
    "B",             # flake8-bugbear
    "S",             # bandit security
    "UP",            # pyupgrade
]
ignore = []

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]  # allow assert in tests only
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Ruff configs: none found"
        return (
            f"Ruff configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Ruff analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            select = ", ".join(info.select_rules) if info.select_rules else "default"
            ignore = ", ".join(info.ignore_rules) if info.ignore_rules else "none"
            lines.append(f"  - {info.path}: select={select}, ignore={ignore}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
