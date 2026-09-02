"""MypyAnalyzer — audit mypy.ini, setup.cfg, and pyproject.toml [tool.mypy] for type-safety risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "mypy.ini",
    ".mypy.ini",
    "setup.cfg",
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
IGNORE_MISSING_IMPORTS_PATTERN = re.compile(
    r"ignore_missing_imports\s*=\s*true\b",
    re.IGNORECASE,
)
FOLLOW_IMPORTS_SKIP_PATTERN = re.compile(
    r"follow_imports\s*=\s*[\"']?skip[\"']?\b",
    re.IGNORECASE,
)
DISALLOW_UNTYPED_DEFS_FALSE_PATTERN = re.compile(
    r"disallow_untyped_defs\s*=\s*false\b",
    re.IGNORECASE,
)
CHECK_UNTYPED_DEFS_FALSE_PATTERN = re.compile(
    r"check_untyped_defs\s*=\s*false\b",
    re.IGNORECASE,
)
WARN_RETURN_ANY_FALSE_PATTERN = re.compile(
    r"warn_return_any\s*=\s*false\b",
    re.IGNORECASE,
)
ALLOW_UNTYPED_GLOBALS_PATTERN = re.compile(
    r"allow_untyped_globals\s*=\s*true\b",
    re.IGNORECASE,
)
ALLOW_REDEFINITION_PATTERN = re.compile(
    r"allow_redefinition\s*=\s*true\b",
    re.IGNORECASE,
)
DISABLE_ERROR_CODE_PATTERN = re.compile(
    r"disable_error_code\s*=\s*\[[^\]]*[\"'](?:import-untyped|no-untyped-def|"
    r"no-untyped-call|attr-defined|assignment|misc)[\"']",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"exclude\s*=\s*[^\n]*(?:^|\s|,)(?:src|lib|app)(?:/|\s|,|$)",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(
    r"strict\s*=\s*false\b",
    re.IGNORECASE,
)
WARN_UNUSED_IGNORES_FALSE_PATTERN = re.compile(
    r"warn_unused_ignores\s*=\s*false\b",
    re.IGNORECASE,
)
MYPY_PATH_INSECURE_PATTERN = re.compile(
    r"mypy_path\s*=\s*[\"']?(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
PER_MODULE_IGNORE_PATTERN = re.compile(
    r"\[(?:mypy-|tool\.mypy\.overrides\.)(?:settings|config|secrets?|auth|"
    r"credentials?|security)\.",
    re.IGNORECASE,
)
MYPY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]mypy(?:\.[^\]]+)?|mypy(?:-[^\]]+)?)\]",
    re.IGNORECASE,
)
SETUP_CFG_MYPY_SECTION = re.compile(r"^\[mypy(?:-[^\]]+)?\]", re.IGNORECASE | re.MULTILINE)


@dataclass
class MypyFinding:
    """A security or best-practice issue in a mypy configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MypyInfo:
    """Parsed metadata about a mypy configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    strict: bool | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class MypyStats:
    """Aggregate mypy analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name in ("mypy.ini", ".mypy.ini"):
        return "ini"
    if name == "setup.cfg":
        return "ini"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class MypyAnalyzer:
    """Audit mypy configuration for type-safety and security hygiene risks.

    Scans mypy.ini, .mypy.ini, setup.cfg [mypy], and pyproject.toml [tool.mypy]
    for ignore_missing_imports, follow_imports=skip, disabled strict mode,
    per-module overrides on sensitive modules, hardcoded secrets, and broad
    exclude patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MypyFinding] | None = None
        self._stats: MypyStats | None = None
        self._infos: list[MypyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return mypy configuration paths found in the project."""
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
                if "[tool.mypy" not in text and "[tool:mypy" not in text:
                    continue
            if name == "setup.cfg":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not SETUP_CFG_MYPY_SECTION.search(text):
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MypyFinding],
        info: MypyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = MYPY_SECTION_PATTERN.match(stripped) or SETUP_CFG_MYPY_SECTION.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if PER_MODULE_IGNORE_PATTERN.search(stripped):
            findings.append(
                MypyFinding(
                    kind="per_module_sensitive_override",
                    severity="high",
                    message="per-module mypy override on sensitive module — avoid relaxing checks on auth/config code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in mypy config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in mypy config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in mypy config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_MISSING_IMPORTS_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="ignore_missing_imports",
                    severity="medium",
                    message="ignore_missing_imports=true hides import errors — scope to specific modules only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FOLLOW_IMPORTS_SKIP_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="follow_imports_skip",
                    severity="high",
                    message="follow_imports=skip bypasses type checking for imports — narrow scope",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            info.strict = False
            findings.append(
                MypyFinding(
                    kind="strict_disabled",
                    severity="medium",
                    message="strict=false disables mypy strict mode — enable strict for safer typing",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"strict\s*=\s*true\b", stripped, re.IGNORECASE):
            info.strict = True

        if DISALLOW_UNTYPED_DEFS_FALSE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="disallow_untyped_defs_false",
                    severity="medium",
                    message="disallow_untyped_defs=false allows untyped function definitions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHECK_UNTYPED_DEFS_FALSE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="check_untyped_defs_false",
                    severity="medium",
                    message="check_untyped_defs=false skips type checking in untyped functions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WARN_RETURN_ANY_FALSE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="warn_return_any_false",
                    severity="low",
                    message="warn_return_any=false silences Any return warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_UNTYPED_GLOBALS_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="allow_untyped_globals",
                    severity="medium",
                    message="allow_untyped_globals=true permits untyped module-level variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_REDEFINITION_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="allow_redefinition",
                    severity="low",
                    message="allow_redefinition=true can mask variable shadowing bugs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_ERROR_CODE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="disabled_error_codes",
                    severity="high",
                    message="disable_error_code suppresses type-safety errors — remove broad disables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from type checking — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WARN_UNUSED_IGNORES_FALSE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="warn_unused_ignores_false",
                    severity="low",
                    message="warn_unused_ignores=false hides stale type: ignore comments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MYPY_PATH_INSECURE_PATTERN.search(line):
            findings.append(
                MypyFinding(
                    kind="insecure_mypy_path",
                    severity="high",
                    message="mypy_path points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_mypy_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name in ("mypy.ini", ".mypy.ini"):
            return True
        if path.name == "setup.cfg":
            if SETUP_CFG_MYPY_SECTION.match(line.strip()):
                return True
            if line.strip().startswith("[") and not SETUP_CFG_MYPY_SECTION.match(line.strip()):
                return False
            return in_section
        if path.name == "pyproject.toml":
            if MYPY_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not MYPY_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        return True

    def _analyze_file(self, path: Path) -> tuple[list[MypyFinding], MypyInfo]:
        findings: list[MypyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MypyInfo(path=rel, file_kind=_file_kind(path))

        info = MypyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_mypy_section = path.name in ("mypy.ini", ".mypy.ini")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in ("setup.cfg", "pyproject.toml"):
                in_mypy_section = self._in_mypy_section(line, in_mypy_section, path)
                if not in_mypy_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[MypyFinding]:
        """Scan mypy configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MypyFinding] = []
        infos: list[MypyInfo] = []
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
        self._stats = MypyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MypyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MypyInfo]:
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
        """Scaffold a hardened mypy configuration template."""
        return """\
# Generated by DevAI MypyAnalyzer
[tool.mypy]
python_version = "3.10"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
check_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_configs = true
show_error_codes = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Mypy configs: none found"
        return (
            f"Mypy configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Mypy analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            strict = "enabled" if info.strict else ("disabled" if info.strict is False else "default")
            lines.append(f"  - {info.path}: strict={strict}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
