"""JestAnalyzer — audit Jest config and package.json jest blocks for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "jest.config.js",
    "jest.config.ts",
    "jest.config.mjs",
    "jest.config.cjs",
    "jest.config.json",
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
IGNORE_SECURITY_TESTS_PATTERN = re.compile(
    r"testPathIgnorePatterns.*(?:security|auth|permission|secret|credential)",
    re.IGNORECASE,
)
COVERAGE_EXCLUDE_ALL_PATTERN = re.compile(
    r"collectCoverageFrom.*\[\s*\]|coveragePathIgnorePatterns.*\[\s*\"\*\*\"\s*\]",
    re.IGNORECASE,
)
SYMLINKS_ENABLED_PATTERN = re.compile(
    r"(?:enableSymlinks|followSymlinks)\s*[:=]\s*true", re.IGNORECASE
)
MOCKS_DISABLED_PATTERN = re.compile(
    r"(?:clearMocks|resetMocks|restoreMocks)\s*[:=]\s*false", re.IGNORECASE
)
GLOBAL_SETUP_PATTERN = re.compile(
    r"(?:globalSetup|globalTeardown|setupFilesAfterEnv|setupFiles)\s*[:=]",
    re.IGNORECASE,
)
MODULE_MAPPER_REDIRECT_PATTERN = re.compile(
    r"(?:\.\./|/etc/|\.ssh/)", re.IGNORECASE
)


@dataclass
class JestFinding:
    """A security or best-practice issue in a Jest configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JestInfo:
    """Parsed metadata about a Jest configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    presets: list[str] = field(default_factory=list)
    setup_files: list[str] = field(default_factory=list)
    test_environment: str = ""


@dataclass
class JestStats:
    """Aggregate Jest analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith("jest.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".json") or name == "package.json":
        return "json"
    if name.endswith((".ts", ".mts")):
        return "typescript"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class JestAnalyzer:
    """Audit Jest configuration for security and CI risks.

    Scans jest.config.* and package.json jest blocks for hardcoded secrets,
    insecure preset URLs, dangerous globalSetup/setupFiles, testPathIgnorePatterns
    that skip security tests, disabled mock resets, symlink following, and
    moduleNameMapper redirects outside the project root.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JestFinding] | None = None
        self._stats: JestStats | None = None
        self._infos: list[JestInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Jest configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("jest.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "jest" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[JestFinding],
        info: JestInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        preset_match = re.search(r'["\']?preset["\']?\s*[:=]', stripped, re.IGNORECASE)
        if preset_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.presets:
                    info.presets.append(value)

        env_match = re.search(r'["\']?testEnvironment["\']?\s*[:=]', stripped, re.IGNORECASE)
        if env_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.test_environment = value

        if GLOBAL_SETUP_PATTERN.search(stripped):
            for value in _extract_string_literals(stripped):
                if value and value not in info.setup_files:
                    info.setup_files.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Jest config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Jest config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Jest config — use HTTPS for presets and reporters",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                JestFinding(
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
                JestFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Jest config — avoid piping remote scripts in setup",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Jest config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Jest config or setup reference — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_SECURITY_TESTS_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="security_tests_ignored",
                    severity="medium",
                    message="testPathIgnorePatterns may skip security-related tests — review exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COVERAGE_EXCLUDE_ALL_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="coverage_disabled",
                    severity="medium",
                    message="coverage collection appears disabled or overly narrow — verify CI gates",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SYMLINKS_ENABLED_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="symlinks_enabled",
                    severity="medium",
                    message="symlink following enabled — may resolve paths outside project root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MOCKS_DISABLED_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="mocks_not_reset",
                    severity="low",
                    message="mock reset/clear disabled — tests may leak state across files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MODULE_MAPPER_REDIRECT_PATTERN.search(line) and (
            "moduleNameMapper" in line
            or "rootDir" in line
            or "<rootDir>" in line
            or "mapper" in line.lower()
        ):
            findings.append(
                JestFinding(
                    kind="module_mapper_redirect",
                    severity="high",
                    message="moduleNameMapper redirects outside project — review for dependency confusion",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?bail["\']?\s*:\s*false', stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="bail_disabled",
                    severity="low",
                    message="bail: false runs all tests after first failure — consider bail in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[JestFinding], JestInfo]:
        findings: list[JestFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, JestInfo(path=rel, file_kind=_file_kind(path))

        info = JestInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[JestFinding]:
        """Scan Jest configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JestFinding] = []
        infos: list[JestInfo] = []
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
        self._stats = JestStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JestStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JestInfo]:
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
        """Scaffold a hardened Jest config template."""
        return """\
// Generated by DevAI JestAnalyzer
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  bail: process.env.CI ? 1 : 0,
  collectCoverageFrom: ["src/**/*.{js,ts,tsx}", "!src/**/*.d.ts"],
  coveragePathIgnorePatterns: ["/node_modules/", "/dist/"],
  modulePathIgnorePatterns: ["<rootDir>/dist/"],
  testPathIgnorePatterns: ["/node_modules/", "/dist/"],
  haste: {
    enableSymlinks: false,
  },
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Jest configs: none found"
        return (
            f"Jest configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Jest analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            env = info.test_environment or "default"
            lines.append(f"  - {info.path}: env={env}, presets={len(info.presets)}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
