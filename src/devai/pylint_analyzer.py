"""PylintAnalyzer — audit pylint configs for init-hook, disable=all, and unsafe-load-any-extension."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".pylintrc",
    "pylintrc",
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
INIT_HOOK_PATTERN = re.compile(r"init-hook\s*=", re.IGNORECASE)
DISABLE_ALL_PATTERN = re.compile(
    r"disable\s*=\s*(?:[\"']all[\"']|all\b|\[[^\]]*[\"']all[\"'])",
    re.IGNORECASE,
)
UNSAFE_LOAD_ANY_EXTENSION_PATTERN = re.compile(
    r"unsafe-load-any-extension\s*=\s*(?:yes|true|1)\b",
    re.IGNORECASE,
)
LOAD_PLUGINS_PATTERN = re.compile(
    r"load-plugins\s*=\s*(?:\[[^\]]*[\"'][^\"']+[\"']|[^\s#\n]+)",
    re.IGNORECASE,
)
IGNORE_PATTERNS_SOURCE_PATTERN = re.compile(
    r"ignore-patterns\s*=\s*[^\n]*(?:^|\s|,)(?:src|lib|app)(?:/|\s|,|$)",
    re.IGNORECASE,
)
ALLOW_GLOBAL_UNUSED_VARIABLES_PATTERN = re.compile(
    r"allow-global-unused-variables\s*=\s*(?:yes|true)\b",
    re.IGNORECASE,
)
PYLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pylint(?:\.[^\]]+)?|pylint|MASTER|MESSAGES CONTROL)\]",
    re.IGNORECASE,
)
SETUP_CFG_PYLINT_SECTION = re.compile(r"^\[pylint", re.IGNORECASE | re.MULTILINE)


@dataclass
class PylintFinding:
    """A security or best-practice issue in a pylint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PylintInfo:
    """Parsed metadata about a pylint configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    sections: list[str] = field(default_factory=list)
    has_init_hook: bool = False
    unsafe_extensions: bool = False


@dataclass
class PylintStats:
    """Aggregate pylint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name in (".pylintrc", "pylintrc"):
        return "ini"
    if name == "setup.cfg":
        return "ini"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class PylintAnalyzer:
    """Audit pylint configuration for security and linting hygiene risks.

    Scans .pylintrc, pylintrc, setup.cfg [pylint], and pyproject.toml [tool.pylint]
    for init-hook arbitrary code execution, disable=all, unsafe-load-any-extension,
    hardcoded secrets, and broad ignore patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PylintFinding] | None = None
        self._stats: PylintStats | None = None
        self._infos: list[PylintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pylint configuration paths found in the project."""
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
                if "[tool.pylint" not in text and "[tool:pylint" not in text:
                    continue
            if name == "setup.cfg":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not SETUP_CFG_PYLINT_SECTION.search(text):
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PylintFinding],
        info: PylintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        section_match = PYLINT_SECTION_PATTERN.match(stripped) or SETUP_CFG_PYLINT_SECTION.match(
            stripped
        )
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in pylint config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in pylint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in pylint config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INIT_HOOK_PATTERN.search(line):
            info.has_init_hook = True
            findings.append(
                PylintFinding(
                    kind="init_hook",
                    severity="high",
                    message="init-hook executes arbitrary Python at pylint startup — remove or sandbox",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_ALL_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="disable_all",
                    severity="high",
                    message="disable=all turns off every pylint check — remove or narrow disables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_LOAD_ANY_EXTENSION_PATTERN.search(line):
            info.unsafe_extensions = True
            findings.append(
                PylintFinding(
                    kind="unsafe_load_any_extension",
                    severity="high",
                    message="unsafe-load-any-extension=yes allows loading untrusted pylint plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOAD_PLUGINS_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="load_plugins",
                    severity="medium",
                    message="load-plugins loads third-party pylint extensions — pin and audit plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_PATTERNS_SOURCE_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="ignore_patterns_source",
                    severity="medium",
                    message="ignore-patterns skips source directories — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_GLOBAL_UNUSED_VARIABLES_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="allow_global_unused_variables",
                    severity="low",
                    message="allow-global-unused-variables=yes hides dead code in modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[PylintFinding], PylintInfo]:
        findings: list[PylintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PylintInfo(path=rel, file_kind=_file_kind(path))

        info = PylintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_pylint_section = path.name not in ("pyproject.toml", "setup.cfg")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                if PYLINT_SECTION_PATTERN.match(line.strip()):
                    in_pylint_section = True
                elif line.strip().startswith("[") and not PYLINT_SECTION_PATTERN.match(line.strip()):
                    in_pylint_section = False
                if not in_pylint_section:
                    continue
            elif path.name == "setup.cfg":
                if SETUP_CFG_PYLINT_SECTION.match(line.strip()):
                    in_pylint_section = True
                elif line.strip().startswith("[") and not SETUP_CFG_PYLINT_SECTION.match(line.strip()):
                    in_pylint_section = False
                if not in_pylint_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PylintFinding]:
        """Scan pylint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PylintFinding] = []
        infos: list[PylintInfo] = []
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
        self._stats = PylintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PylintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PylintInfo]:
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
        """Scaffold a hardened pylint configuration template."""
        return """\
# Generated by DevAI PylintAnalyzer
[tool.pylint.main]
unsafe-load-any-extension = false
load-plugins = []

[tool.pylint."messages control"]
disable = []
enable = ["all"]

[tool.pylint.format]
max-line-length = 88
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pylint configs: none found"
        return (
            f"Pylint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pylint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            hook = "yes" if info.has_init_hook else "no"
            unsafe = "yes" if info.unsafe_extensions else "no"
            lines.append(
                f"  - {info.path}: init-hook={hook}, unsafe-extensions={unsafe}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
