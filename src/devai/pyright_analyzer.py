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
TYPE_CHECKING_OFF_PATTERN = re.compile(
    r"typeCheckingMode\s*[=:]\s*[\"']?(?:off|basic)[\"']?\b",
    re.IGNORECASE,
)
REPORT_MISSING_IMPORTS_FALSE_PATTERN = re.compile(
    r"reportMissingImports\s*[=:]\s*false\b",
    re.IGNORECASE,
)
REPORT_UNKNOWN_MEMBER_FALSE_PATTERN = re.compile(
    r"reportUnknownMemberType\s*[=:]\s*false\b",
    re.IGNORECASE,
)
REPORT_GENERAL_TYPE_FALSE_PATTERN = re.compile(
    r"reportGeneralTypeIssues\s*[=:]\s*false\b",
    re.IGNORECASE,
)
REPORT_MISSING_TYPE_STUBS_FALSE_PATTERN = re.compile(
    r"reportMissingTypeStubs\s*[=:]\s*false\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"exclude\s*[=:]\s*[^\n]*\b(?:src|lib|app|package)\b",
    re.IGNORECASE,
)
EXTRA_PATHS_INSECURE_PATTERN = re.compile(
    r"extraPaths\s*[=:].*(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
STUB_PATH_INSECURE_PATTERN = re.compile(
    r"stubPath\s*[=:]\s*[\"']?(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
USE_LIBRARY_CODE_FALSE_PATTERN = re.compile(
    r"useLibraryCodeForTypes\s*[=:]\s*false\b",
    re.IGNORECASE,
)
STRICT_NONE_CHECKING_FALSE_PATTERN = re.compile(
    r"strictParameterNoneValueChecking\s*[=:]\s*false\b",
    re.IGNORECASE,
)
EXECUTION_ENV_SENSITIVE_PATTERN = re.compile(
    r"(?:settings|config|secrets?|auth|credentials?|security)",
    re.IGNORECASE,
)
PYRIGHT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pyright(?:\.[^\]]+)?|tool[.:]basedpyright(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
REPORT_OPTIONAL_MEMBER_ACCESS_FALSE_PATTERN = re.compile(
    r"reportOptionalMemberAccess\s*[=:]\s*false\b",
    re.IGNORECASE,
)
REPORT_PRIVATE_USAGE_FALSE_PATTERN = re.compile(
    r"reportPrivateUsage\s*[=:]\s*false\b",
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
    if name == "pyrightconfig.json":
        return "json"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class PyrightAnalyzer:
    """Audit Pyright configuration for type-safety and security hygiene risks.

    Scans pyrightconfig.json and pyproject.toml [tool.pyright] / [tool.basedpyright]
    for disabled type checking, suppressed report rules, broad exclude patterns,
    insecure extraPaths/stubPath, and hardcoded secrets.
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
                if "[tool.pyright" not in text and "[tool.basedpyright" not in text:
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
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = PYRIGHT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if EXECUTION_ENV_SENSITIVE_PATTERN.search(stripped) and re.search(
            r"(?:reportMissingImports|reportGeneralTypeIssues|typeCheckingMode)\s*[=:]\s*"
            r"(?:false|off|basic)",
            stripped,
            re.IGNORECASE,
        ):
            findings.append(
                PyrightFinding(
                    kind="execution_env_sensitive_relaxed",
                    severity="high",
                    message="execution environment relaxes checks on sensitive module — avoid weakening auth/config paths",
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

        if TYPE_CHECKING_OFF_PATTERN.search(line):
            mode_match = re.search(
                r"typeCheckingMode\s*[=:]\s*[\"']?(\w+)[\"']?",
                stripped,
                re.IGNORECASE,
            )
            if mode_match:
                info.type_checking_mode = mode_match.group(1).lower()
            findings.append(
                PyrightFinding(
                    kind="type_checking_relaxed",
                    severity="high",
                    message="typeCheckingMode is off or basic — use standard or strict for safer typing",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        mode_match = re.search(
            r"typeCheckingMode\s*[=:]\s*[\"']?(strict|standard)[\"']?",
            stripped,
            re.IGNORECASE,
        )
        if mode_match:
            info.type_checking_mode = mode_match.group(1).lower()

        if REPORT_MISSING_IMPORTS_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_missing_imports_false",
                    severity="medium",
                    message="reportMissingImports=false hides import errors — keep enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNKNOWN_MEMBER_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_unknown_member_false",
                    severity="medium",
                    message="reportUnknownMemberType=false silences member type errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_GENERAL_TYPE_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_general_type_false",
                    severity="high",
                    message="reportGeneralTypeIssues=false suppresses core type errors",
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
                    message="reportMissingTypeStubs=false hides missing stub warnings",
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

        if EXTRA_PATHS_INSECURE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_extra_paths",
                    severity="high",
                    message="extraPaths points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STUB_PATH_INSECURE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="insecure_stub_path",
                    severity="high",
                    message="stubPath points outside the project — restrict to trusted paths",
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
                    message="useLibraryCodeForTypes=false reduces type inference from library code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_NONE_CHECKING_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="strict_none_checking_false",
                    severity="medium",
                    message="strictParameterNoneValueChecking=false weakens None parameter checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_OPTIONAL_MEMBER_ACCESS_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_optional_member_false",
                    severity="medium",
                    message="reportOptionalMemberAccess=false hides optional access errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_PRIVATE_USAGE_FALSE_PATTERN.search(line):
            findings.append(
                PyrightFinding(
                    kind="report_private_usage_false",
                    severity="low",
                    message="reportPrivateUsage=false silences private member access warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_pyright_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == "pyrightconfig.json":
            return True
        if path.name == "pyproject.toml":
            if PYRIGHT_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not PYRIGHT_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        return True

    def _normalize_json_line(self, line: str) -> str:
        """Convert JSON key-value syntax to a form compatible with config scanners."""
        stripped = line.strip().rstrip(",")
        match = re.match(
            r'^"([^"]+)"\s*:\s*(.+)$',
            stripped,
        )
        if not match:
            return line
        key, value = match.group(1), match.group(2).strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return f"{key} = {value}"

    def _scan_json_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PyrightFinding],
        info: PyrightInfo,
    ) -> None:
        normalized = self._normalize_json_line(line)
        self._scan_line(normalized, lineno, rel, findings, info)

    def _analyze_json_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        findings: list[PyrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PyrightInfo(path=rel, file_kind=_file_kind(path))

        info = PyrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        try:
            data = json.loads("\n".join(raw_lines))
            mode = data.get("typeCheckingMode")
            if isinstance(mode, str):
                info.type_checking_mode = mode.lower()
        except (json.JSONDecodeError, TypeError):
            pass

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_json_line(raw.rstrip(), lineno, rel, findings, info)

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
            in_pyright_section = self._in_pyright_section(line, in_pyright_section, path)
            if not in_pyright_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[PyrightFinding], PyrightInfo]:
        if path.name == "pyrightconfig.json":
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
# Generated by DevAI PyrightAnalyzer
[tool.pyright]
pythonVersion = "3.10"
typeCheckingMode = "standard"
reportMissingImports = true
reportUnknownMemberType = true
reportGeneralTypeIssues = true
reportMissingTypeStubs = true
reportOptionalMemberAccess = true
reportPrivateUsage = true
strictParameterNoneValueChecking = true
useLibraryCodeForTypes = true
exclude = [
    "**/node_modules",
    "**/__pycache__",
    ".venv",
    "build",
    "dist",
]
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
