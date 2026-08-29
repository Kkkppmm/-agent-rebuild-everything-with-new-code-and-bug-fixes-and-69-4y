"""MochaAnalyzer — audit Mocha config and .mocharc.* for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".mocharc.json",
    ".mocharc.js",
    ".mocharc.cjs",
    ".mocharc.mjs",
    ".mocharc.yaml",
    ".mocharc.yml",
    "mocha.opts",
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
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b|child_process)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
REQUIRE_OUTSIDE_PATTERN = re.compile(
    r'["\']?(?:require|spec|file|extension)["\']?\s*[:=].*(?:\.\./|/etc/|\.ssh/)',
    re.IGNORECASE,
)
ALLOW_UNCAUGHT_PATTERN = re.compile(
    r'["\']?allowUncaught["\']?\s*[:=]\s*true', re.IGNORECASE
)
FORBID_ONLY_DISABLED_PATTERN = re.compile(
    r'["\']?forbidOnly["\']?\s*[:=]\s*false', re.IGNORECASE
)
TIMEOUT_ZERO_PATTERN = re.compile(
    r'["\']?timeout["\']?\s*[:=]\s*0\b', re.IGNORECASE
)
IGNORE_SECURITY_TESTS_PATTERN = re.compile(
    r'["\']?(?:grep|invert)["\']?\s*[:=].*(?:security|auth|permission|secret|credential)|'
    r"/(?:security|auth|permission|secret|credential)/",
    re.IGNORECASE,
)
INSPECT_PATTERN = re.compile(
    r"(?:--inspect(?:-brk)?|NODE_OPTIONS.*inspect)", re.IGNORECASE
)
REPORTER_INSECURE_PATTERN = re.compile(
    r"reporter(?:-option|-options)?\s*[:=].*http://",
    re.IGNORECASE,
)


@dataclass
class MochaFinding:
    """A security or best-practice issue in a Mocha configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MochaInfo:
    """Parsed metadata about a Mocha configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    ui: str = ""
    require_files: list[str] = field(default_factory=list)
    timeout_ms: int | None = None


@dataclass
class MochaStats:
    """Aggregate Mocha analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith(".mocharc.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith((".json", ".mocharc.json")) or name == "package.json":
        return "json"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    if name.endswith((".ts", ".mts")):
        return "typescript"
    if name.endswith((".js", ".cjs", ".mjs")) or name == "mocha.opts":
        return "javascript"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class MochaAnalyzer:
    """Audit Mocha configuration for security and CI risks.

    Scans .mocharc.*, mocha.opts, and package.json mocha blocks for hardcoded
    secrets, require/spec paths outside the project, allowUncaught, disabled
    forbidOnly, zero timeouts, security test exclusions, and Node inspect flags.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MochaFinding] | None = None
        self._stats: MochaStats | None = None
        self._infos: list[MochaInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Mocha configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".mocharc.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "mocha" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MochaFinding],
        info: MochaInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        ui_match = re.search(r'["\']?ui["\']?\s*[:=]', stripped, re.IGNORECASE)
        if ui_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.ui = value

        require_match = re.search(r'["\']?require["\']?\s*[:=]', stripped, re.IGNORECASE)
        if require_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.require_files:
                    info.require_files.append(value)

        timeout_match = re.search(r'["\']?timeout["\']?\s*[:=]\s*(\d+)', stripped, re.IGNORECASE)
        if timeout_match:
            info.timeout_ms = int(timeout_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Mocha config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Mocha config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Mocha config — use HTTPS for reporters and hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Mocha config — avoid piping remote scripts in require hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Mocha config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Mocha config or require reference — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REQUIRE_OUTSIDE_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="require_outside_project",
                    severity="high",
                    message="require/spec/file path outside project — review for dependency confusion",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_UNCAUGHT_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="allow_uncaught",
                    severity="medium",
                    message="allowUncaught: true — uncaught exceptions may mask test failures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORBID_ONLY_DISABLED_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="forbid_only_disabled",
                    severity="medium",
                    message="forbidOnly: false allows .only in CI — enable forbidOnly in CI pipelines",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TIMEOUT_ZERO_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="timeout_zero",
                    severity="medium",
                    message="timeout: 0 disables test timeouts — hung tests may block CI indefinitely",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_SECURITY_TESTS_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="security_tests_ignored",
                    severity="medium",
                    message="grep/invert may skip security-related tests — review exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSPECT_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="node_inspect",
                    severity="high",
                    message="Node --inspect flag in Mocha config — remote debugging may expose the process",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORTER_INSECURE_PATTERN.search(line):
            findings.append(
                MochaFinding(
                    kind="insecure_reporter",
                    severity="high",
                    message="reporter configured with insecure HTTP endpoint",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?bail["\']?\s*:\s*false', stripped, re.IGNORECASE):
            findings.append(
                MochaFinding(
                    kind="bail_disabled",
                    severity="low",
                    message="bail: false runs all tests after first failure — consider bail in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[MochaFinding], MochaInfo]:
        findings: list[MochaFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, MochaInfo(path=rel, file_kind=_file_kind(path))

        info = MochaInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[MochaFinding]:
        """Scan Mocha configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MochaFinding] = []
        infos: list[MochaInfo] = []
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
        self._stats = MochaStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MochaStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MochaInfo]:
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
        """Scaffold a hardened .mocharc.json template."""
        return """\
{
  "// Generated by DevAI MochaAnalyzer": "",
  "ui": "bdd",
  "timeout": 10000,
  "bail": true,
  "forbidOnly": true,
  "allowUncaught": false,
  "require": ["test/setup.js"],
  "spec": ["test/**/*.spec.js"],
  "reporter": "spec",
  "reporter-option": ["maxDiffSize=0"]
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Mocha configs: none found"
        return (
            f"Mocha configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Mocha analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ui = info.ui or "default"
            lines.append(f"  - {info.path}: ui={ui}, require={len(info.require_files)}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
