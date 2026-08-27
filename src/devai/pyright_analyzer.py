"""PyrightAnalyzer — audit pyrightconfig.json and pyproject.toml [tool.pyright] for type-check risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pyrightconfig.json",
    "pyproject.toml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r'"?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|'
    r'private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)"?\s*[=:]\s*'
    r'["\']?[^"\'\s${}][^"\'<]*["\']?',
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
TYPE_CHECKING_OFF_PATTERN = re.compile(
    r'"?typeCheckingMode"?\s*[=:]\s*["\']?(?:off|none)["\']?',
    re.IGNORECASE,
)
TYPE_CHECKING_BASIC_PATTERN = re.compile(
    r'"?typeCheckingMode"?\s*[=:]\s*["\']?basic["\']?',
    re.IGNORECASE,
)
REPORT_MISSING_IMPORTS_FALSE_PATTERN = re.compile(
    r'"?reportMissingImports"?\s*[=:]\s*false\b',
    re.IGNORECASE,
)
REPORT_MISSING_TYPE_STUBS_FALSE_PATTERN = re.compile(
    r'"?reportMissingTypeStubs"?\s*[=:]\s*false\b',
    re.IGNORECASE,
)
REPORT_GENERAL_TYPE_ISSUES_FALSE_PATTERN = re.compile(
    r'"?reportGeneralTypeIssues"?\s*[=:]\s*false\b',
    re.IGNORECASE,
)
EXTRA_PATHS_INSECURE_PATTERN = re.compile(
    r'"?(?:extraPaths|stubPath)"?\s*[=:]\s*[^\n]*(?:/tmp/|/etc/|\.\./)',
    re.IGNORECASE,
)
EXECUTION_ENVIRONMENT_SENSITIVE_PATTERN = re.compile(
    r'"?executionEnvironments"?\s*[=:][^\n]*(?:settings|config|secrets?|auth)',
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(
    r'"?strict"?\s*[=:]\s*false\b',
    re.IGNORECASE,
)
PYRIGHT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pyright(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)


@dataclass
class PyrightFinding:
    """A security or best-practice issue in a Pyright configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PyrightInfo:
    """Parsed metadata about a Pyright configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    type_checking_mode: str | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class PyrightStats:
    """Aggregate Pyright analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name == "pyrightconfig.json":
        return "json"
    return "unknown"


class PyrightAnalyzer:
    """Audit Pyright configuration for type-safety and security hygiene risks.

    Scans pyrightconfig.json and pyproject.toml [tool.pyright] for relaxed
    typeCheckingMode, disabled reportMissingImports, insecure extraPaths/stubPath,
    and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PyrightFinding] | None = None
        self._stats: PyrightStats | None = None
        self._infos: list[PyrightInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Pyright configuration paths found in the project."""
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
                if "[tool.pyright" not in text and "[tool:pyright" not in text:
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PyrightFinding],
        info: PyrightInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            return

        section_match = PYRIGHT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if TYPE_CHECKING_OFF_PATTERN.search(line):
            info.type_checking_mode = "off"
            findings.append(
                PyrightFinding(
                    kind="type_checking_off",
                    severity="high",
                    message="typeCheckingMode=off disables type checking — use standard or strict",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TYPE_CHECKING_BASIC_PATTERN.search(line):
            info.type_checking_mode = "basic"
            findings.append(
                PyrightFinding(
                    kind="type_checking_basic",
                    severity="medium",
                    message="typeCheckingMode=basic is relaxed — prefer standard or strict",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Pyright config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Pyright config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Pyright config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_MISSING_IMPORTS_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_missing_imports_false",
                    severity="high",
                    message="reportMissingImports=false hides unresolved imports — keep enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_MISSING_TYPE_STUBS_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_missing_type_stubs_false",
                    severity="low",
                    message="reportMissingTypeStubs=false silences missing stub warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_GENERAL_TYPE_ISSUES_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_general_type_issues_false",
                    severity="high",
                    message="reportGeneralTypeIssues=false suppresses type errors — keep enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXTRA_PATHS_INSECURE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_paths",
                    severity="high",
                    message="extraPaths/stubPath points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXECUTION_ENVIRONMENT_SENSITIVE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="execution_environment_sensitive",
                    severity="medium",
                    message="executionEnvironments override on sensitive module — avoid relaxing checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="strict_false",
                    severity="medium",
                    message="strict=false disables strict type checking — enable strict mode",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_pyright_section(self, line: str, in_section: bool) -> bool:
        if PYRIGHT_SECTION_PATTERN.match(line.strip()):
            return True
        if line.strip().startswith("[") and not PYRIGHT_SECTION_PATTERN.match(line.strip()):
            return False
        return in_section

    def _analyze_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        findings: list[PyrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PyrightInfo(path=rel, file_kind=_file_kind(path))

        info = PyrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = path.name == "pyrightconfig.json"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                in_section = self._in_pyright_section(line, in_section)
                if not in_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PyrightFinding]:
        """Scan Pyright configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PyrightFinding] = []
        infos: list[PyrightInfo] = []
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
        self._stats = PyrightStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PyrightStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PyrightInfo]:
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
        """Scaffold a hardened Pyright configuration template."""
        return """\
// Generated by DevAI PyrightAnalyzer
{
  "typeCheckingMode": "standard",
  "pythonVersion": "3.10",
  "reportMissingImports": true,
  "reportMissingTypeStubs": true,
  "reportGeneralTypeIssues": true,
  "strict": ["reportPrivateUsage"]
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pyright configs: none found"
        return (
            f"Pyright configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pyright analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            mode = info.type_checking_mode if info.type_checking_mode else "default"
            lines.append(f"  - {info.path}: typeCheckingMode={mode}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
