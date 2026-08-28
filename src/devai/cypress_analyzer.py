"""CypressAnalyzer — audit Cypress E2E config for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "cypress.config.js",
    "cypress.config.ts",
    "cypress.config.mjs",
    "cypress.config.cjs",
    "cypress.json",
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
CHROME_WEB_SECURITY_OFF_PATTERN = re.compile(
    r'["\']?chromeWebSecurity["\']?\s*[:=]\s*false', re.IGNORECASE
)
MODIFY_OBSTRUCTIVE_PATTERN = re.compile(
    r'["\']?(?:modifyObstructiveCode|experimentalModifyObstructiveThirdPartyCode)["\']?\s*[:=]\s*true',
    re.IGNORECASE,
)
ARTIFACT_LEAK_PATTERN = re.compile(
    r"(?:screenshotsFolder|videosFolder|downloadsFolder|trashFolder)\s*[:=].*"
    r"(?:/tmp|/var/tmp|/dev/shm|C:\\\\Temp|/public/)",
    re.IGNORECASE,
)
FIXTURES_OUTSIDE_PATTERN = re.compile(
    r'(?:fixturesFolder|supportFile)\s*[:=].*(?:\.\./|/etc/|\.ssh/)',
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r'env\s*:\s*\{[^}]*(?:password|secret|api[_-]?key|token|credential)',
    re.IGNORECASE,
)
WATCH_IN_CI_PATTERN = re.compile(
    r'["\']?watchForFileChanges["\']?\s*[:=]\s*true', re.IGNORECASE
)
EXPERIMENTAL_ALL_SPECS_PATTERN = re.compile(
    r'["\']?experimentalRunAllSpecs["\']?\s*[:=]\s*true', re.IGNORECASE
)


@dataclass
class CypressFinding:
    """A security or best-practice issue in a Cypress configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CypressInfo:
    """Parsed metadata about a Cypress configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    base_url: str = ""
    support_file: str = ""
    has_env_block: bool = False


@dataclass
class CypressStats:
    """Aggregate Cypress analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


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


class CypressAnalyzer:
    """Audit Cypress configuration for security and CI risks.

    Scans cypress.config.*, cypress.json, and package.json cypress blocks for
    disabled chromeWebSecurity, hardcoded secrets in env, insecure baseUrl,
    modifyObstructiveCode, artifact paths to world-readable directories, and
    fixtures/supportFile paths outside the project root.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CypressFinding] | None = None
        self._stats: CypressStats | None = None
        self._infos: list[CypressInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Cypress configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("cypress.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "cypress" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CypressFinding],
        info: CypressInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        base_match = re.search(r'["\']?baseUrl["\']?\s*[:=]', stripped, re.IGNORECASE)
        if base_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.base_url = value

        support_match = re.search(r'["\']?supportFile["\']?\s*[:=]', stripped, re.IGNORECASE)
        if support_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.support_file = value

        if re.search(r'["\']?env["\']?\s*[:=]', stripped, re.IGNORECASE):
            info.has_env_block = True

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Cypress config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Cypress config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Cypress config — use HTTPS for baseUrl",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                CypressFinding(
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
                CypressFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Cypress config — avoid piping remote scripts in setupNodeEvents",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Cypress config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Cypress config or supportFile — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHROME_WEB_SECURITY_OFF_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="chrome_web_security_off",
                    severity="high",
                    message="chromeWebSecurity disabled — same-origin policy bypassed in tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MODIFY_OBSTRUCTIVE_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="modify_obstructive_code",
                    severity="medium",
                    message="modifyObstructiveCode enabled — may mask real browser security behavior",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_SECRET_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="env_secret",
                    severity="high",
                    message="secrets in Cypress env block — use cypress.env.json excluded from VCS or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ARTIFACT_LEAK_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="artifact_leak",
                    severity="medium",
                    message="screenshots/videos/downloads written to world-readable path — use CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FIXTURES_OUTSIDE_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="fixtures_outside",
                    severity="high",
                    message="fixturesFolder or supportFile path outside project — review for credential exposure",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WATCH_IN_CI_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="watch_in_ci",
                    severity="low",
                    message="watchForFileChanges enabled — disable in CI for deterministic runs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXPERIMENTAL_ALL_SPECS_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="experimental_all_specs",
                    severity="low",
                    message="experimentalRunAllSpecs enabled — may run unintended spec files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[CypressFinding], CypressInfo]:
        findings: list[CypressFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, CypressInfo(path=rel, file_kind=_file_kind(path))

        info = CypressInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[CypressFinding]:
        """Scan Cypress configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CypressFinding] = []
        infos: list[CypressInfo] = []
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
        self._stats = CypressStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CypressStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CypressInfo]:
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
        """Scaffold a hardened Cypress config template."""
        return """\
// Generated by DevAI CypressAnalyzer
import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    baseUrl: process.env.CYPRESS_BASE_URL || "http://localhost:3000",
    supportFile: "cypress/support/e2e.ts",
    specPattern: "cypress/e2e/**/*.cy.{js,ts}",
    chromeWebSecurity: true,
    watchForFileChanges: !process.env.CI,
    video: true,
    screenshotOnRunFailure: true,
    retries: { runMode: 2, openMode: 0 },
    setupNodeEvents(on, config) {
      return config;
    },
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Cypress configs: none found"
        return (
            f"Cypress configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Cypress analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            base = info.base_url or "default"
            lines.append(
                f"  - {info.path}: baseUrl={base}, env_block={info.has_env_block}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
