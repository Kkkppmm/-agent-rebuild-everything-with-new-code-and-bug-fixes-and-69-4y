"""PylintAnalyzer — audit pylint configs for lint hygiene and security risks."""

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
INIT_HOOK_EXEC_PATTERN = re.compile(
    r"init-hook\s*=\s*[^\n]*(?:exec|eval|__import__|subprocess|os\.system)",
    re.IGNORECASE,
)
UNSAFE_LOAD_EXTENSION_PATTERN = re.compile(
    r"unsafe-load-any-extension\s*=\s*(?:yes|true|1)\b",
    re.IGNORECASE,
)
DISABLE_ALL_PATTERN = re.compile(
    r"disable\s*=\s*(?:[^\n]*\ball\b|all\b)",
    re.IGNORECASE,
)
DISABLE_SECURITY_PATTERN = re.compile(
    r"disable\s*=\s*[^\n]*(?:exec-used|eval-used|hardcoded-password|"
    r"subprocess-run-check|subprocess-popen-preexec-fn|dangerous-default-value|"
    r"sql-injection|shell-injection|unspecified-encoding)",
    re.IGNORECASE,
)
IGNORE_SOURCE_PATTERN = re.compile(
    r"(?:ignore|ignore-paths)\s*=\s*[^\n]*(?:^|\s|,)(?:src|lib|app)(?:/|\s|,|$)",
    re.IGNORECASE,
)
IGNORE_PATHS_BROAD_PATTERN = re.compile(
    r"ignore-paths\s*=\s*\[[^\]]*[\"']\*\*\/\*[\"']",
    re.IGNORECASE,
)
FAIL_UNDER_LOW_PATTERN = re.compile(
    r"fail-under\s*=\s*(?:[0-4](?:\.\d+)?|0)\b",
    re.IGNORECASE,
)
LOAD_PLUGINS_PATH_PATTERN = re.compile(
    r"load-plugins\s*=\s*[^\n]*(?:/tmp/|\.\./|/etc/)",
    re.IGNORECASE,
)
IGNORED_MODULES_BROAD_PATTERN = re.compile(
    r"ignored-modules\s*=\s*(?:\*(?:\s|$)|[^\n]*\ball\b)",
    re.IGNORECASE,
)
EXTENSION_PKG_ALLOW_LIST_BROAD_PATTERN = re.compile(
    r"extension-pkg-allow-list\s*=\s*\[[^\]]*[\"']\*(?:\/\*)?[\"']",
    re.IGNORECASE,
)
REPORTS_NO_PATTERN = re.compile(r"reports\s*=\s*(?:no|false|0)\b", re.IGNORECASE)
ALLOW_GLOBAL_UNUSED_PATTERN = re.compile(
    r"allow-global-unused-variables\s*=\s*(?:yes|true|1)\b",
    re.IGNORECASE,
)
PYLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pylint(?:\.[^\]]+)?|pylint(?:\.[^\]]+)?|MASTER|MESSAGES CONTROL|"
    r"REPORTS|BASIC|FORMAT|TYPECHECK|VARIABLES|CLASSES|DESIGN|IMPORTS|EXCEPTIONS|"
    r"SIMILARITIES|SPELLING|LOGGING|MISCELLANEOUS|STRING)\]",
    re.IGNORECASE,
)
SETUP_CFG_PYLINT_SECTION = re.compile(
    r"^\[pylint(?:\.[^\]]+)?\]",
    re.IGNORECASE | re.MULTILINE,
)


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
    fail_under: float | None = None
    disabled_rules: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


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


def _extract_disabled_rules(line: str) -> list[str]:
    match = re.search(r"disable\s*=\s*(.+)$", line.strip(), re.IGNORECASE)
    if not match:
        return []
    value = match.group(1).strip()
    if value.startswith("["):
        return re.findall(r'["\']([^"\']+)["\']', value)
    return [part.strip() for part in value.split(",") if part.strip()]


def _extract_fail_under(line: str) -> float | None:
    match = re.search(
        r"fail-under\s*=\s*(\d+(?:\.\d+)?)\b",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return float(match.group(1))


class PylintAnalyzer:
    """Audit pylint configuration for lint hygiene and security risks.

    Scans .pylintrc, pylintrc, setup.cfg [pylint], and pyproject.toml [tool.pylint]
    for init-hook code execution, unsafe-load-any-extension, disable=all,
    disabled security rules, broad ignore patterns, hardcoded secrets, and
    low fail-under thresholds.
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

        fail_under = _extract_fail_under(stripped)
        if fail_under is not None:
            info.fail_under = fail_under

        disabled = _extract_disabled_rules(stripped)
        if disabled:
            info.disabled_rules.extend(disabled)

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
            severity = "high" if INIT_HOOK_EXEC_PATTERN.search(line) else "medium"
            message = (
                "init-hook with exec/eval/subprocess — arbitrary code execution at pylint startup"
                if severity == "high"
                else "init-hook runs arbitrary Python at pylint startup — avoid in shared configs"
            )
            findings.append(
                PylintFinding(
                    kind="init_hook",
                    severity=severity,
                    message=message,
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_LOAD_EXTENSION_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="unsafe_load_extension",
                    severity="high",
                    message="unsafe-load-any-extension=yes allows loading untrusted C extensions",
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
                    message="disable=all silences all pylint checks — use targeted disables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_SECURITY_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="disable_security_rules",
                    severity="high",
                    message="security-related pylint rules disabled — re-enable exec/eval/password checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_SOURCE_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="ignore_source",
                    severity="medium",
                    message="ignore skips source directories from linting — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_PATHS_BROAD_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="ignore_paths_broad",
                    severity="medium",
                    message="ignore-paths includes **/* — linting is effectively disabled",
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
                    message="fail-under < 5 allows very low code quality — raise to 8+",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOAD_PLUGINS_PATH_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="load_plugins_untrusted_path",
                    severity="medium",
                    message="load-plugins references untrusted path — only load vetted plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORED_MODULES_BROAD_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="ignored_modules_broad",
                    severity="medium",
                    message="ignored-modules=* or all skips import analysis — narrow module list",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXTENSION_PKG_ALLOW_LIST_BROAD_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="extension_pkg_allow_list_broad",
                    severity="medium",
                    message="extension-pkg-allow-list includes wildcard — restrict to known packages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORTS_NO_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="reports_disabled",
                    severity="low",
                    message="reports=no hides pylint summary output — enable in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_GLOBAL_UNUSED_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="allow_global_unused",
                    severity="low",
                    message="allow-global-unused-variables=yes hides dead code — prefer explicit cleanup",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_pylint_section(self, path: Path, line: str, file_kind: str) -> bool:
        stripped = line.strip()
        if file_kind == "ini" and path.name in (".pylintrc", "pylintrc"):
            return True
        if PYLINT_SECTION_PATTERN.match(stripped) or SETUP_CFG_PYLINT_SECTION.match(stripped):
            return True
        return False

    def _analyze_file(self, path: Path) -> tuple[list[PylintFinding], PylintInfo]:
        findings: list[PylintFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PylintInfo(path=rel, file_kind=file_kind)

        info = PylintInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)
        in_section = path.name in (".pylintrc", "pylintrc")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()

            if stripped.startswith("[") and not stripped.startswith("[#"):
                in_section = bool(
                    PYLINT_SECTION_PATTERN.match(stripped)
                    or SETUP_CFG_PYLINT_SECTION.match(stripped)
                    or path.name in (".pylintrc", "pylintrc")
                )
                if in_section:
                    section = stripped.strip("[]")
                    if section not in info.sections:
                        info.sections.append(section)
                continue

            if not in_section:
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
fail-under = 8.0
ignore-paths = [
    "^\\\\.venv/.*$",
    "^build/.*$",
    "^dist/.*$",
]

[tool.pylint."messages control"]
disable = [
    "raw-checker-failed",
    "bad-inline-option",
    "locally-disabled",
    "file-ignored",
    "suppressed-message",
    "useless-suppression",
    "deprecated-pragma",
    "use-symbolic-message-instead",
]

[tool.pylint.reports]
reports = true
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
            disabled = ", ".join(info.disabled_rules[:5]) if info.disabled_rules else "none"
            lines.append(f"  - {info.path}: fail-under={fail_under}, disabled={disabled}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
