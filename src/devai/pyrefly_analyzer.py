"""PyreflyAnalyzer — audit pyrefly.toml and pyproject.toml [tool.pyrefly] for type-safety risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pyrefly.toml",
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
PYREFLY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pyrefly(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
PYREFLY_TOML_SECTION_PATTERN = re.compile(
    r"^\[(?:errors|sub-config)(?:\.[^\]]+)?\]",
    re.IGNORECASE,
)
PRESET_OFF_PATTERN = re.compile(
    r'preset\s*=\s*["\']?off["\']?(?:\s|$|,)',
    re.IGNORECASE,
)
PRESET_LEGACY_PATTERN = re.compile(
    r'preset\s*=\s*["\']?legacy["\']?(?:\s|$|,)',
    re.IGNORECASE,
)
PRESET_BASIC_PATTERN = re.compile(
    r'preset\s*=\s*["\']?basic["\']?(?:\s|$|,)',
    re.IGNORECASE,
)
REPLACE_IMPORTS_WITH_ANY_PATTERN = re.compile(
    r"replace-imports-with-any\s*=\s*\[",
    re.IGNORECASE,
)
DISABLE_TYPE_ERRORS_IDE_PATTERN = re.compile(
    r"disable-type-errors-in-ide\s*=\s*true\b",
    re.IGNORECASE,
)
PERMISSIVE_IGNORES_PATTERN = re.compile(
    r"permissive-ignores\s*=\s*true\b",
    re.IGNORECASE,
)
IGNORE_ERRORS_GENERATED_PATTERN = re.compile(
    r"ignore-errors-in-generated-code\s*=\s*true\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"project-excludes\s*=\s*[^\n]*(?:\"src\"|'src'|\"lib\"|'lib'|\"app\"|'app'|\bsrc/|\blib/|\bapp/)",
    re.IGNORECASE,
)
INSECURE_PATH_PATTERN = re.compile(
    r"(?:search-path|typeshed-path|site-package-path)\s*[=:\[][^\n]*(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
CRITICAL_ERROR_DISABLED_PATTERN = re.compile(
    r"(?:bad-assignment|bad-return|invalid-argument|invalid-return-type|"
    r"missing-import|unbound-name|possibly-missing-import|"
    r"possibly-unresolved-reference)\s*=\s*(?:false|False|\"ignore\"|'ignore')",
    re.IGNORECASE,
)
BROAD_REPLACE_IMPORTS_PATTERN = re.compile(
    r'replace-imports-with-any\s*=\s*\[[^\]]*(?:\"\*\"|\'\*\'|\"\*\*\"|\'\*\*\'|\"\.\*\"|\'\.\*\')',
    re.IGNORECASE,
)


@dataclass
class PyreflyFinding:
    """A security or best-practice issue in a Pyrefly configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PyreflyInfo:
    """Parsed metadata about a Pyrefly configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    preset: str | None = None


@dataclass
class PyreflyStats:
    """Aggregate Pyrefly analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyrefly.toml":
        return "pyrefly.toml"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class PyreflyAnalyzer:
    """Audit Meta Pyrefly configuration for type-safety and security hygiene risks.

    Scans pyrefly.toml and pyproject.toml [tool.pyrefly] for disabled presets,
    broad import overrides, relaxed error settings, insecure paths, and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PyreflyFinding] | None = None
        self._stats: PyreflyStats | None = None
        self._infos: list[PyreflyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Pyrefly configuration paths found in the project."""
        found: list[Path] = []
        pyrefly_toml = self.root / "pyrefly.toml"
        if pyrefly_toml.is_file():
            found.append(pyrefly_toml)
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return found
            if "[tool.pyrefly" in text or "[tool:pyrefly" in text:
                found.append(pyproject)
        return found

    def _in_pyrefly_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == "pyrefly.toml":
            stripped = line.strip()
            if stripped.startswith("[") and not PYREFLY_TOML_SECTION_PATTERN.match(stripped):
                if stripped.startswith("[") and stripped != "[errors]" and not stripped.startswith(
                    "[[sub-config"
                ):
                    return False
            return True
        if path.name == "pyproject.toml":
            stripped = line.strip()
            if PYREFLY_SECTION_PATTERN.match(stripped):
                return True
            if stripped.startswith("[") and not PYREFLY_SECTION_PATTERN.match(stripped):
                return False
            return in_section
        return True

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PyreflyFinding],
        info: PyreflyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PyreflyFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Pyrefly config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PyreflyFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Pyrefly config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PyreflyFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Pyrefly config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PRESET_OFF_PATTERN.search(stripped):
            info.preset = "off"
            findings.append(
                PyreflyFinding(
                    kind="preset_off",
                    severity="high",
                    message='preset="off" silences all Pyrefly checks — use default or strict',
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PRESET_LEGACY_PATTERN.search(stripped):
            info.preset = "legacy"
            findings.append(
                PyreflyFinding(
                    kind="preset_legacy",
                    severity="medium",
                    message='preset="legacy" relaxes checks for mypy migration — migrate to default or strict',
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PRESET_BASIC_PATTERN.search(stripped):
            info.preset = "basic"
            findings.append(
                PyreflyFinding(
                    kind="preset_basic",
                    severity="low",
                    message='preset="basic" only reports high-confidence errors — consider default or strict',
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPLACE_IMPORTS_WITH_ANY_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="replace_imports_with_any",
                    severity="high",
                    message="replace-imports-with-any masks unresolved imports — narrow to specific modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROAD_REPLACE_IMPORTS_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="broad_replace_imports",
                    severity="medium",
                    message="replace-imports-with-any uses broad wildcards — narrow to specific modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CRITICAL_ERROR_DISABLED_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="critical_error_disabled",
                    severity="high",
                    message="critical type-safety error disabled — keep import and assignment errors enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_TYPE_ERRORS_IDE_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="disable_type_errors_ide",
                    severity="medium",
                    message="disable-type-errors-in-ide hides errors in the editor — keep IDE feedback enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PERMISSIVE_IGNORES_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="permissive_ignores",
                    severity="medium",
                    message="permissive-ignores=true accepts malformed type: ignore comments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ERRORS_GENERATED_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="ignore_errors_generated",
                    severity="low",
                    message="ignore-errors-in-generated-code=true skips generated code — verify stubs are correct",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="project-excludes skips src/lib/app — verify type checking still covers production code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PATH_PATTERN.search(stripped):
            findings.append(
                PyreflyFinding(
                    kind="insecure_path",
                    severity="high",
                    message="search-path/typeshed-path points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[PyreflyFinding], PyreflyInfo]:
        findings: list[PyreflyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PyreflyInfo(path=rel, file_kind=_file_kind(path))

        info = PyreflyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_pyrefly_section = path.name == "pyrefly.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                in_pyrefly_section = self._in_pyrefly_section(line, in_pyrefly_section, path)
                if not in_pyrefly_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PyreflyFinding]:
        """Scan Pyrefly configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PyreflyFinding] = []
        infos: list[PyreflyInfo] = []
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
        self._stats = PyreflyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PyreflyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PyreflyInfo]:
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
        """Scaffold a hardened Pyrefly configuration template."""
        return """\
# Generated by DevAI PyreflyAnalyzer
[tool.pyrefly]
preset = "strict"
project-includes = ["src"]
project-excludes = ["**/__pycache__", ".venv", "build", "dist"]
search-path = ["src"]
use-ignore-files = true
permissive-ignores = false
disable-type-errors-in-ide = false

[tool.pyrefly.errors]
bad-assignment = true
bad-return = true
invalid-argument = true
missing-import = true
unbound-name = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pyrefly configs: none found"
        return (
            f"Pyrefly configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pyrefly analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
