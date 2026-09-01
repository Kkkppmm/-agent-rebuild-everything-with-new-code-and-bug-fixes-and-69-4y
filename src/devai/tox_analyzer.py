"""ToxAnalyzer — audit tox.ini for security and CI reliability risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("tox.ini",)

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
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|\bos\.system\s*\()",
    re.IGNORECASE,
)
PASSENV_WILDCARD_PATTERN = re.compile(
    r"(?:passenv|pass_env)\s*=\s*\*",
    re.IGNORECASE,
)
ALLOWLIST_WILDCARD_PATTERN = re.compile(
    r"(?:allowlist_externals|whitelist_externals)\s*=\s*\*",
    re.IGNORECASE,
)
IGNORE_ERRORS_PATTERN = re.compile(
    r"ignore_errors\s*=\s*true\b",
    re.IGNORECASE,
)
SKIP_MISSING_INTERPRETERS_PATTERN = re.compile(
    r"skip_missing_interpreters\s*=\s*true\b",
    re.IGNORECASE,
)
CHANGEDIR_OUTSIDE_PATTERN = re.compile(
    r"changedir\s*=\s*(?:\.\./|/etc/|/tmp/|\.ssh/)",
    re.IGNORECASE,
)
INSECURE_PIP_INDEX_PATTERN = re.compile(
    r"(?:--index-url|--extra-index-url|--trusted-host)\s+http://|"
    r"(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL)\s*=\s*http://",
    re.IGNORECASE,
)
INDEXSERVER_CREDENTIALS_PATTERN = re.compile(
    r"^\s*\w+\s*=\s*https?://[^@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s]+#egg=)",
    re.IGNORECASE,
)
ISOLATED_BUILD_DISABLED_PATTERN = re.compile(
    r"isolated_build\s*=\s*false\b",
    re.IGNORECASE,
)
SITEPACKAGES_ENABLED_PATTERN = re.compile(
    r"sitepackages\s*=\s*true\b",
    re.IGNORECASE,
)
SECURITY_ENV_SKIP_PATTERN = re.compile(
    r"(?:envlist|skip)\s*=.*(?:security|auth|permission|secret|credential)",
    re.IGNORECASE,
)
TOX_SECTION_PATTERN = re.compile(r"^\[(?:tox|testenv(?::[^\]]+)?)\]", re.IGNORECASE)


@dataclass
class ToxFinding:
    """A security or best-practice issue in a tox configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ToxInfo:
    """Parsed metadata about a tox configuration file."""

    path: str
    lines: int = 0
    envlist: list[str] = field(default_factory=list)
    testenvs: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class ToxStats:
    """Aggregate tox analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _extract_ini_value(line: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.+)$", line.strip(), re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_testenv_name(line: str) -> str | None:
    match = re.match(r"^\[testenv:(.+)\]", line.strip(), re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


class ToxAnalyzer:
    """Audit tox.ini for security and CI reliability risks.

    Scans tox.ini for hardcoded secrets, passenv=*, allowlist_externals=*,
    ignore_errors, insecure pip indexes, SCM credentials in deps, changedir
    outside the project, and security-related env skips.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ToxFinding] | None = None
        self._stats: ToxStats | None = None
        self._infos: list[ToxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return tox configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ToxFinding],
        info: ToxInfo,
        in_tox_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        envlist = _extract_ini_value(stripped, "envlist")
        if envlist:
            info.envlist = [e.strip() for e in envlist.split(",") if e.strip()]

        commands = _extract_ini_value(stripped, "commands")
        if commands:
            info.commands.append(commands)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in tox config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in tox config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in tox config — use HTTPS for indexes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in tox config — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INDEXSERVER_CREDENTIALS_PATTERN.search(stripped):
            findings.append(
                ToxFinding(
                    kind="indexserver_credentials",
                    severity="high",
                    message="indexserver credentials in tox.ini — use pip config or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in tox deps — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHANGEDIR_OUTSIDE_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="changedir_outside",
                    severity="high",
                    message="changedir points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PASSENV_WILDCARD_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="passenv_wildcard",
                    severity="medium",
                    message="passenv=* forwards all environment variables — prefer explicit passenv lists",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOWLIST_WILDCARD_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="allowlist_wildcard",
                    severity="medium",
                    message="allowlist_externals=* permits any external command — restrict to known tools",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ERRORS_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="ignore_errors",
                    severity="medium",
                    message="ignore_errors=true may hide failing security checks in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_MISSING_INTERPRETERS_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="skip_missing_interpreters",
                    severity="medium",
                    message="skip_missing_interpreters=true may silently skip test environments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PIP_INDEX_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in tox environments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SECURITY_ENV_SKIP_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="security_env_skip",
                    severity="medium",
                    message="envlist/skip may exclude security-related environments — review exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_tox_section and ISOLATED_BUILD_DISABLED_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="isolated_build_disabled",
                    severity="low",
                    message="isolated_build=false may allow build-time dependency injection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SITEPACKAGES_ENABLED_PATTERN.search(line):
            findings.append(
                ToxFinding(
                    kind="sitepackages_enabled",
                    severity="low",
                    message="sitepackages=true may leak global packages into isolated test envs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[ToxFinding], ToxInfo]:
        findings: list[ToxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ToxInfo(path=rel)

        info = ToxInfo(path=rel, lines=len(raw_lines))
        in_tox_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()

            if stripped.startswith("[") and stripped.endswith("]"):
                testenv_name = _extract_testenv_name(stripped)
                if testenv_name and testenv_name not in info.testenvs:
                    info.testenvs.append(testenv_name)
                in_tox_section = bool(TOX_SECTION_PATTERN.match(stripped))
                continue

            self._scan_line(line, lineno, rel, findings, info, in_tox_section)

        return findings, info

    def analyze(self) -> list[ToxFinding]:
        """Scan tox configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ToxFinding] = []
        infos: list[ToxInfo] = []
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
        self._stats = ToxStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ToxStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ToxInfo]:
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
        """Scaffold a hardened tox.ini template."""
        return """\
# Generated by DevAI ToxAnalyzer
[tox]
envlist = py310, py311, py312
isolated_build = true
skip_missing_interpreters = false
requires =
    tox>=4

[testenv]
deps =
    -r{toxinidir}/requirements-test.txt
commands =
    pytest {posargs:tests}
passenv =
    CI
    GITHUB_*
setenv =
    PYTHONWARNINGS = error
allowlist_externals =
    pytest
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Tox configs: none found"
        return (
            f"Tox configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Tox analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            envlist = ", ".join(info.envlist) if info.envlist else "default"
            lines.append(f"  - {info.path}: envlist={envlist}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
