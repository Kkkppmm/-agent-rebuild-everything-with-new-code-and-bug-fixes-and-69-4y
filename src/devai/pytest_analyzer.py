"""PytestAnalyzer — audit pytest.ini, pyproject.toml, and conftest.py for security and CI risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pytest.ini",
    "tox.ini",
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
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(
    r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True",
    re.IGNORECASE,
)
OS_SYSTEM_PATTERN = re.compile(r"\bos\.system\s*\(", re.IGNORECASE)
PDB_IN_ADDOPTS_PATTERN = re.compile(
    r"(?:addopts|--pdb|--trace|--pdbcls)\b",
    re.IGNORECASE,
)
CONTINUE_ON_COLLECTION_PATTERN = re.compile(
    r"(?:--continue-on-collection-errors|continue_on_collection_errors\s*=\s*true)",
    re.IGNORECASE,
)
IGNORE_WARNINGS_PATTERN = re.compile(
    r"(?:filterwarnings\s*=\s*ignore|--disable-warnings|PYTHONWARNINGS\s*=\s*ignore)",
    re.IGNORECASE,
)
IGNORE_SECURITY_TESTS_PATTERN = re.compile(
    r"(?:--ignore=|--ignore-glob=|python_files\s*=|norecursedirs\s*=).*(?:security|auth|permission|secret|credential)",
    re.IGNORECASE,
)
TIMEOUT_ZERO_PATTERN = re.compile(
    r"(?:timeout\s*=\s*0\b|--timeout=0\b|timeout_method\s*=\s*thread\b.*timeout\s*=\s*0)",
    re.IGNORECASE,
)
NO_COV_PATTERN = re.compile(
    r"(?:--no-cov\b|coverage\s*=\s*false\b|addopts.*--no-cov)",
    re.IGNORECASE,
)
PLUGIN_OUTSIDE_PATTERN = re.compile(
    r"(?:-p\s+|\bplugins\s*=).*(?:\.\./|/etc/|\.ssh/)",
    re.IGNORECASE,
)
ALLOW_EMPTY_PATTERN = re.compile(
    r"(?:--allow-empty|--allow-no-tests|empty_parameter_set_mark\s*=\s*skip\b)",
    re.IGNORECASE,
)
RUN_XFAIL_PATTERN = re.compile(r"--runxfail\b", re.IGNORECASE)
TLS_VERIFY_DISABLED_PATTERN = re.compile(
    r"(?:PYTHONHTTPSVERIFY\s*=\s*0|verify\s*=\s*False|ssl\._create_unverified_context)",
    re.IGNORECASE,
)
PYTEST_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pytest(?:\.ini_options)?|pytest)\]",
    re.IGNORECASE,
)


@dataclass
class PytestFinding:
    """A security or best-practice issue in a pytest configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PytestInfo:
    """Parsed metadata about a pytest configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    addopts: str = ""
    testpaths: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)


@dataclass
class PytestStats:
    """Aggregate pytest analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name == "conftest.py":
        return "python"
    if name.endswith((".ini", ".cfg")):
        return "ini"
    return "unknown"


def _extract_ini_value(line: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", line.strip(), re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


class PytestAnalyzer:
    """Audit pytest configuration for security and CI risks.

    Scans pytest.ini, tox.ini, setup.cfg, pyproject.toml, and conftest.py for
    hardcoded secrets, eval/exec, shell=True subprocess calls, --pdb in CI,
    security test exclusions, disabled coverage, and TLS verification bypass.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PytestFinding] | None = None
        self._stats: PytestStats | None = None
        self._infos: list[PytestInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pytest configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if not path.is_file():
                continue
            if name in ("tox.ini", "setup.cfg", "pyproject.toml"):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if name == "pyproject.toml":
                    if "[tool.pytest" not in text and "[tool:pytest" not in text:
                        continue
                elif "[pytest" not in text.lower():
                    continue
            found.append(path)

        for path in sorted(self.root.rglob("conftest.py")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PytestFinding],
        info: PytestInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        addopts = _extract_ini_value(stripped, "addopts")
        if addopts:
            info.addopts = addopts

        testpaths = _extract_ini_value(stripped, "testpaths")
        if testpaths:
            info.testpaths = [p.strip() for p in testpaths.split() if p.strip()]

        plugins = _extract_ini_value(stripped, "plugins")
        if plugins:
            info.plugins = [p.strip() for p in plugins.split(",") if p.strip()]

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in pytest config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in pytest config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in pytest config — use HTTPS for fixtures and plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="eval_exec",
                    severity="high",
                    message="eval/exec in pytest config or conftest — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHELL_TRUE_PATTERN.search(line) or OS_SYSTEM_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="shell_execution",
                    severity="high",
                    message="shell execution in conftest — prefer subprocess without shell=True",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PLUGIN_OUTSIDE_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="plugin_outside_project",
                    severity="high",
                    message="pytest plugin path outside project — review for dependency confusion",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_DISABLED_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled in pytest config — re-enable certificate checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PDB_IN_ADDOPTS_PATTERN.search(line) and info.file_kind != "python":
            findings.append(
                PytestFinding(
                    kind="pdb_in_addopts",
                    severity="medium",
                    message="--pdb/--trace in addopts may hang CI — remove debug flags from CI configs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CONTINUE_ON_COLLECTION_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="continue_on_collection_errors",
                    severity="medium",
                    message="continue on collection errors may hide broken imports in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_WARNINGS_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="warnings_ignored",
                    severity="medium",
                    message="broad warning suppression may hide deprecations and security notices",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_SECURITY_TESTS_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="security_tests_ignored",
                    severity="medium",
                    message="ignore/norecursedirs may skip security-related tests — review exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TIMEOUT_ZERO_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="timeout_zero",
                    severity="medium",
                    message="timeout disabled — hung tests may block CI indefinitely",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_COV_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="coverage_disabled",
                    severity="low",
                    message="coverage disabled in pytest config — consider enforcing coverage in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_EMPTY_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="allow_empty_tests",
                    severity="low",
                    message="allow-empty/no-tests options may hide missing test suites in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RUN_XFAIL_PATTERN.search(line):
            findings.append(
                PytestFinding(
                    kind="runxfail",
                    severity="low",
                    message="--runxfail treats expected failures as passes — avoid in CI gates",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[PytestFinding], PytestInfo]:
        findings: list[PytestFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, PytestInfo(path=rel, file_kind=_file_kind(path))

        info = PytestInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        in_pytest_section = path.name == "conftest.py" or path.name == "pytest.ini"
        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in ("tox.ini", "setup.cfg", "pyproject.toml"):
                if PYTEST_SECTION_PATTERN.match(line.strip()):
                    in_pytest_section = True
                    continue
                if line.strip().startswith("[") and not PYTEST_SECTION_PATTERN.match(line.strip()):
                    in_pytest_section = False
                if not in_pytest_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PytestFinding]:
        """Scan pytest configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PytestFinding] = []
        infos: list[PytestInfo] = []
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
        self._stats = PytestStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PytestStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PytestInfo]:
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
        """Scaffold a hardened pytest.ini template."""
        return """\
# Generated by DevAI PytestAnalyzer
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = --strict-markers --strict-config -ra --cov=src --cov-report=term-missing
filterwarnings = error
timeout = 300
markers =
    slow: marks tests as slow (deselect with '-m \"not slow\"')
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pytest configs: none found"
        return (
            f"Pytest configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pytest analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            addopts = info.addopts or "default"
            lines.append(f"  - {info.path}: addopts={addopts[:60]}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
