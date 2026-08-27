"""PylintAnalyzer — audit Pylint configs for broad disables, unsafe init-hook, and security rule suppression."""

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
DISABLE_ALL_PATTERN = re.compile(
    r"disable\s*=\s*[^\n]*\bALL\b",
    re.IGNORECASE,
)
UNSAFE_INIT_HOOK_PATTERN = re.compile(
    r"init-hook\s*=\s*[^\n]*(?:exec|eval|compile|__import__|subprocess|os\.system)",
    re.IGNORECASE,
)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r"disable\s*=\s*[^\n]*(?:import-error|exec-used|bad-builtin|subprocess-run-check|"
    r"subprocess-popen-preexec-fn|shell-true|dangerous-default-value)",
    re.IGNORECASE,
)
IGNORE_SENSITIVE_MODULE_PATTERN = re.compile(
    r"\[(?:tool[.:]pylint[.:]messages_control|pylint|MASTER)\][^\n]*"
    r"(?:settings|config|secrets?|auth)\.py",
    re.IGNORECASE,
)
LOAD_PLUGINS_UNSAFE_PATTERN = re.compile(
    r"load-plugins\s*=\s*[^\n]*(?:pylint_django|pylint_flask)",
    re.IGNORECASE,
)
PYLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pylint(?:\.[^\]]+)?|pylint|MASTER)\]",
    re.IGNORECASE,
)
SETUP_CFG_PYLINT_SECTION = re.compile(r"^\[pylint\]", re.IGNORECASE)
FAIL_UNDER_LOW_PATTERN = re.compile(
    r"fail-under\s*=\s*(?:[0-4]|[0-9]\.\d)\b",
    re.IGNORECASE,
)


@dataclass
class PylintFinding:
    """A security or best-practice issue in a Pylint configuration file."""

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
    """Parsed metadata about a Pylint configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    fail_under: float | None = None
    sections: list[str] = field(default_factory=list)


@dataclass
class PylintStats:
    """Aggregate Pylint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    if name in (".pylintrc", "pylintrc", "setup.cfg"):
        return "ini"
    return "unknown"


def _extract_float_value(line: str, key: str) -> float | None:
    match = re.search(
        rf"^{re.escape(key)}\s*[=:]\s*(\d+(?:\.\d+)?)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return float(match.group(1))


class PylintAnalyzer:
    """Audit Pylint configuration for security and linting hygiene risks.

    Scans .pylintrc, pylintrc, setup.cfg [pylint], and pyproject.toml [tool.pylint]
    for disable=ALL, unsafe init-hook, disabled security rules, low fail-under,
    and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PylintFinding] | None = None
        self._stats: PylintStats | None = None
        self._infos: list[PylintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Pylint configuration paths found in the project."""
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
                if "[tool.pylint" not in text and "[tool:pylint" not in text:
                    continue
            elif name == "setup.cfg":
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

        fail_under = _extract_float_value(stripped, "fail-under")
        if fail_under is not None:
            info.fail_under = fail_under

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Pylint config — use env vars or CI secrets",
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
                    message="AWS access key in Pylint config — rotate and use env vars",
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
                    message="insecure HTTP URL in Pylint config — use HTTPS endpoints",
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
                    message="disable=ALL disables all lint rules — remove broad disables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_INIT_HOOK_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="unsafe_init_hook",
                    severity="high",
                    message="init-hook executes dangerous code at pylint startup — remove or sandbox",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="disabled_security_rules",
                    severity="high",
                    message="security-related pylint rules disabled — keep exec/subprocess checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FAIL_UNDER_LOW_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="fail_under_low",
                    severity="medium",
                    message="fail-under < 5 allows low-quality code — raise quality gate",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOAD_PLUGINS_UNSAFE_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="framework_plugins",
                    severity="low",
                    message="framework pylint plugins loaded — verify plugin trust and pin versions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_pylint_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name in (".pylintrc", "pylintrc"):
            return True
        if path.name in ("setup.cfg", "pyproject.toml"):
            if PYLINT_SECTION_PATTERN.match(line.strip()) or SETUP_CFG_PYLINT_SECTION.match(
                line.strip()
            ):
                return True
            if line.strip().startswith("[") and not (
                PYLINT_SECTION_PATTERN.match(line.strip())
                or SETUP_CFG_PYLINT_SECTION.match(line.strip())
            ):
                return False
            return in_section
        return True

    def _analyze_file(self, path: Path) -> tuple[list[PylintFinding], PylintInfo]:
        findings: list[PylintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PylintInfo(path=rel, file_kind=_file_kind(path))

        info = PylintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = path.name in (".pylintrc", "pylintrc")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name in (".pylintrc", "pylintrc", "setup.cfg", "pyproject.toml"):
                in_section = self._in_pylint_section(line, in_section, path)
                if not in_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PylintFinding]:
        """Scan Pylint configs and return findings."""
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
        """Scaffold a hardened Pylint configuration template."""
        return """\
# Generated by DevAI PylintAnalyzer
[tool.pylint.main]
fail-under = 8.0

[tool.pylint.messages_control]
disable = []

[tool.pylint.basic]
good-names = ["i", "j", "k", "ex", "_"]
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
            fail_under = info.fail_under if info.fail_under is not None else "default"
            lines.append(f"  - {info.path}: fail-under={fail_under}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
