"""PyrightAnalyzer — audit pyrightconfig.json and pyproject.toml [tool.pyright] for type-safety risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pyrightconfig.json",
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
def _json_key(key: str) -> str:
    return rf"[\"']?{re.escape(key)}[\"']?"


TYPE_CHECKING_OFF_PATTERN = re.compile(
    rf"{_json_key('typeCheckingMode')}\s*[=:]\s*[\"']?(?:off|basic)[\"']?(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
REPORT_MISSING_IMPORTS_FALSE_PATTERN = re.compile(
    rf"{_json_key('reportMissingImports')}\s*[=:]\s*false(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
REPORT_OPTIONAL_FALSE_PATTERN = re.compile(
    r"report(?:OptionalMemberAccess|OptionalSubscript|OptionalCall|OptionalIterable|"
    r"OptionalContextManager|OptionalOperand)\s*[=:]\s*false(?:\s*[,}\]]|$)",
    re.IGNORECASE,
)
USE_LIBRARY_CODE_FALSE_PATTERN = re.compile(
    rf"{_json_key('useLibraryCodeForTypes')}\s*[=:]\s*false(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(
    rf"{_json_key('strict')}\s*[=:]\s*(?:\[\s*\]|false)(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    rf"{_json_key('exclude')}\s*[=:]\s*\[[^\]]*[\"'](?:src|lib|app)[\"']",
    re.IGNORECASE,
)
EXTRA_PATH_INSECURE_PATTERN = re.compile(
    rf"{_json_key('extraPaths')}\s*[=:]\s*\[[^\]]*[\"'](?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
VENV_PATH_INSECURE_PATTERN = re.compile(
    rf"{_json_key('venvPath')}\s*[=:]\s*[\"'](?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
REPORT_GENERAL_FALSE_PATTERN = re.compile(
    rf"{_json_key('reportGeneralTypeIssues')}\s*[=:]\s*false(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
REPORT_PRIVATE_FALSE_PATTERN = re.compile(
    rf"{_json_key('reportPrivateUsage')}\s*[=:]\s*false(?:\s*[,}}\]]|$)",
    re.IGNORECASE,
)
REPORT_OPTIONAL_MEMBER_FALSE_PATTERN = re.compile(
    rf"{_json_key('reportOptionalMemberAccess')}\s*[=:]\s*false(?:\s*[,}}\]]|$)",
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
    type_checking_mode: str = ""
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
    if path.name.endswith(".json"):
        return "json"
    if path.name.endswith(".toml"):
        return "toml"
    return "unknown"


def _extract_string_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*[\"']([^\"']+)[\"']\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1)


class PyrightAnalyzer:
    """Audit Pyright configuration for type-safety and security risks.

    Scans pyrightconfig.json and pyproject.toml [tool.pyright] for relaxed
    type checking, disabled report rules, insecure extraPaths, and broad
    exclude patterns.
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
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if name == "pyrightconfig.json":
                found.append(path)
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
        if not stripped or stripped.startswith("#"):
            return

        section_match = PYRIGHT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        mode = _extract_string_value(stripped, "typeCheckingMode")
        if mode is not None:
            info.type_checking_mode = mode

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

        if TYPE_CHECKING_OFF_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="type_checking_relaxed",
                    severity="high",
                    message="typeCheckingMode off/basic weakens static analysis — use standard or strict",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_MISSING_IMPORTS_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_missing_imports_false",
                    severity="medium",
                    message="reportMissingImports=false hides unresolved imports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_OPTIONAL_FALSE_PATTERN.search(line) or REPORT_OPTIONAL_MEMBER_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_optional_false",
                    severity="medium",
                    message="disabled optional report rules hide None-related type errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if USE_LIBRARY_CODE_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="use_library_code_false",
                    severity="low",
                    message="useLibraryCodeForTypes=false reduces type inference from libraries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="strict_disabled",
                    severity="medium",
                    message="strict mode disabled — enable strict type checking",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from type checking — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXTRA_PATH_INSECURE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_extra_paths",
                    severity="high",
                    message="extraPaths includes /tmp, /etc, or parent dirs — restrict to project paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VENV_PATH_INSECURE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_venv_path",
                    severity="high",
                    message="venvPath points outside project — use a local .venv directory",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_GENERAL_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_general_false",
                    severity="medium",
                    message="reportGeneralTypeIssues=false hides general type errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_PRIVATE_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_private_false",
                    severity="low",
                    message="reportPrivateUsage=false allows private API misuse",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        findings: list[PyrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PyrightInfo(path=rel, file_kind=_file_kind(path))

        info = PyrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads("\n".join(raw_lines))
            if isinstance(data, dict):
                mode = data.get("typeCheckingMode")
                if isinstance(mode, str):
                    info.type_checking_mode = mode
        except (json.JSONDecodeError, OSError):
            pass

        return findings, info

    def _analyze_toml_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        findings: list[PyrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PyrightInfo(path=rel, file_kind=_file_kind(path))

        info = PyrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_pyright_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if PYRIGHT_SECTION_PATTERN.match(line.strip()):
                in_pyright_section = True
            elif line.strip().startswith("[") and not PYRIGHT_SECTION_PATTERN.match(line.strip()):
                in_pyright_section = False
            if not in_pyright_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        if path.name.endswith(".json"):
            return self._analyze_json_file(path)
        return self._analyze_toml_file(path)

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
  "reportMissingImports": true,
  "reportOptionalMemberAccess": true,
  "reportGeneralTypeIssues": true,
  "useLibraryCodeForTypes": true,
  "exclude": [
    "**/node_modules",
    "**/__pycache__",
    ".venv"
  ]
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
            mode = info.type_checking_mode or "default"
            lines.append(f"  - {info.path}: typeCheckingMode={mode}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
