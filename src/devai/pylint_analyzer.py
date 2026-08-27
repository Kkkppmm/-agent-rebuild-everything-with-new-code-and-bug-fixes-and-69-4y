"""PylintAnalyzer — audit Pylint configs for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".pylintrc",
    "pylintrc",
    "setup.cfg",
    "tox.ini",
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
PYLINT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]pylint(?:\.[^\]]+)?|pylint(?:\.[^\]]+)?|MASTER|MESSAGES CONTROL|"
    r"FORMAT|BASIC|TYPECHECK|VARIABLES|CLASSES|DESIGN|IMPORTS|EXCEPTIONS|"
    r"SIMILARITIES|SPELLING|LOGGING|REPORTS|REFACTORING|MISCELLANEOUS)\]",
    re.IGNORECASE,
)
SETUP_CFG_PYLINT_SECTION = re.compile(r"^\[pylint\]", re.IGNORECASE | re.MULTILINE)
TOX_PYLINT_SECTION = re.compile(r"^\[pylint\]", re.IGNORECASE | re.MULTILINE)
DISABLE_ALL_PATTERN = re.compile(
    r"(?:disable|enable)\s*=\s*(?:ALL|\*)\b",
    re.IGNORECASE,
)
DISABLE_BROAD_PATTERN = re.compile(
    r"disable\s*=\s*(?:C|R|W|E|F)(?:\s*,\s*(?:C|R|W|E|F))*\b",
    re.IGNORECASE,
)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r"disable\s*=\s*[^\n#]*\b(?:"
    r"exec-used|eval-used|subprocess-run-check|subprocess-popen-preexec-fn|"
    r"hard-coded-password|hardcoded-password|hard-coded-password-string|"
    r"missing-timeout|insecure-hash-function|weak-ssl-version|"
    r"unspecified-encoding|consider-using-with"
    r")\b",
    re.IGNORECASE,
)
IGNORE_SOURCE_PATTERN = re.compile(
    r"(?:ignore|ignore-paths|ignore-patterns)\s*=\s*[^\n#]*\b(?:src|lib|app)\b",
    re.IGNORECASE,
)
MAX_LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"max-line-length\s*=\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\b",
    re.IGNORECASE,
)
MAX_LINE_LENGTH_LOW_PATTERN = re.compile(
    r"max-line-length\s*=\s*(?:[1-9]|[1-5][0-9])\b",
    re.IGNORECASE,
)
FAIL_UNDER_LOW_PATTERN = re.compile(
    r"fail-under\s*=\s*(?:0|[1-4](?:\.\d+)?|5(?:\.0+)?)\b",
    re.IGNORECASE,
)
SCORE_DISABLED_PATTERN = re.compile(
    r"score\s*=\s*(?:no|false|0)\b",
    re.IGNORECASE,
)
UNSAFE_INIT_HOOK_PATTERN = re.compile(
    r"init-hook\s*=\s*[^\n#]*(?:exec\s*\(|eval\s*\(|os\.system|subprocess\.|"
    r"__import__\s*\(|importlib\.import_module)",
    re.IGNORECASE,
)
UNSAFE_LOAD_EXTENSION_PATTERN = re.compile(
    r"unsafe-load-any-extension\s*=\s*(?:yes|true|1)\b",
    re.IGNORECASE,
)
EXTENSION_ALLOW_ALL_PATTERN = re.compile(
    r"extension-pkg-allow-list\s*=\s*(?:\*|ALL)\b",
    re.IGNORECASE,
)
IGNORED_MODULES_BROAD_PATTERN = re.compile(
    r"ignored-modules\s*=\s*[^\n#]*\b(?:src|lib|app|\*)\b",
    re.IGNORECASE,
)
PER_FILE_DISABLE_SECURITY_PATTERN = re.compile(
    r"(?:settings\.py|config\.py|secrets?\.py|auth\.py)\s*:\s*[^\n#]*(?:"
    r"exec-used|eval-used|hard-coded-password|subprocess-run-check"
    r")",
    re.IGNORECASE,
)
MAX_COMPLEXITY_HIGH_PATTERN = re.compile(
    r"max-complexity\s*=\s*(?:[3-9][0-9]|[1-9][0-9]{2,})\b",
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
    max_line_length: int | None = None
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
    if name in (".pylintrc", "pylintrc", "setup.cfg", "tox.ini"):
        return "ini"
    return "unknown"


def _extract_int_value(line: str, key: str) -> int | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return int(match.group(1))


def _extract_float_value(line: str, key: str) -> float | None:
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*(\d+(?:\.\d+)?)\s*$",
        line.strip(),
        re.IGNORECASE,
    )
    if not match:
        return None
    return float(match.group(1))


class PylintAnalyzer:
    """Audit Pylint configuration for lint hygiene and security risks.

    Scans .pylintrc, pylintrc, setup.cfg [pylint], tox.ini [pylint], and
    pyproject.toml [tool.pylint] for broad disable patterns, disabled security
    rules, unsafe init-hook code, source tree exclusions, and hardcoded secrets.
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
            elif name == "tox.ini":
                if not TOX_PYLINT_SECTION.search(text):
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

        section_match = PYLINT_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        line_length = _extract_int_value(stripped, "max-line-length")
        if line_length is not None:
            info.max_line_length = line_length

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
                    message="disable/enable=ALL disables all rules — narrow to specific codes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif DISABLE_BROAD_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="disable_broad",
                    severity="medium",
                    message="disable disables entire rule families — prefer specific codes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="disabled_security_rule",
                    severity="high",
                    message="security-related Pylint rules disabled — keep exec/eval/password checks enabled",
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
                    message="ignore/ignore-paths skips source directories — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MAX_LINE_LENGTH_HIGH_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="max_line_length_high",
                    severity="medium",
                    message="max-line-length > 200 reduces readability — align with Black (88)",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MAX_LINE_LENGTH_LOW_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="max_line_length_low",
                    severity="low",
                    message="max-line-length < 60 causes excessive wrapping — consider 88",
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
                    message="fail-under <= 5 allows very low code quality — raise to 8+",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCORE_DISABLED_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="score_disabled",
                    severity="low",
                    message="score=no hides quality metrics — keep scoring enabled in CI",
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
                    message="init-hook runs dangerous code at startup — remove exec/eval/subprocess calls",
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
                    message="unsafe-load-any-extension=yes allows arbitrary code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXTENSION_ALLOW_ALL_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="extension_allow_all",
                    severity="medium",
                    message="extension-pkg-allow-list=* is overly permissive — list trusted packages",
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
                    message="ignored-modules skips source packages — narrow to third-party only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PER_FILE_DISABLE_SECURITY_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="per_file_security_disable",
                    severity="high",
                    message="per-file disables security rules on sensitive modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MAX_COMPLEXITY_HIGH_PATTERN.search(line):
            findings.append(
                PylintFinding(
                    kind="max_complexity_high",
                    severity="medium",
                    message="max-complexity > 29 allows overly complex functions — tighten to 10-15",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_pylint_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name in (".pylintrc", "pylintrc"):
            return True
        if path.name == "pyproject.toml":
            if PYLINT_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not PYLINT_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        if PYLINT_SECTION_PATTERN.match(line.strip()):
            return True
        if line.strip().startswith("[") and not PYLINT_SECTION_PATTERN.match(line.strip()):
            return False
        return in_section

    def _analyze_file(self, path: Path) -> tuple[list[PylintFinding], PylintInfo]:
        findings: list[PylintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PylintInfo(path=rel, file_kind=_file_kind(path))

        info = PylintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_pylint_section = path.name in (".pylintrc", "pylintrc")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_pylint_section = self._in_pylint_section(line, in_pylint_section, path)
            if not in_pylint_section:
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
[MASTER]
ignore = CVS,.git,__pycache__,.venv,build,dist
unsafe-load-any-extension = no
extension-pkg-allow-list =

[MESSAGES CONTROL]
disable =
    missing-docstring,
    too-few-public-methods,
    fixme
enable =
    exec-used,
    eval-used,
    hard-coded-password-string,
    subprocess-run-check,
    missing-timeout

[FORMAT]
max-line-length = 88

[DESIGN]
max-complexity = 10

[REPORTS]
score = yes
fail-under = 8.0
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "pylint configs: none found"
        return (
            f"pylint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "pylint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            length = info.max_line_length if info.max_line_length is not None else "default"
            fail_under = info.fail_under if info.fail_under is not None else "default"
            lines.append(f"  - {info.path}: max-line-length={length}, fail-under={fail_under}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
