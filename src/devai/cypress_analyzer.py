"""CypressAnalyzer — audit Cypress E2E config for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "cypress.config.ts",
    "cypress.config.js",
    "cypress.config.mjs",
    "cypress.config.cjs",
    "cypress.json",
)
ENV_NAMES = ("cypress.env.json",)

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
INSECURE_BASE_URL_PATTERN = re.compile(
    r'["\']?baseUrl["\']?\s*[:=]\s*["\']http://(?!localhost|127\.0\.0\.1)',
    re.IGNORECASE,
)
VIDEO_ALWAYS_ON_PATTERN = re.compile(
    r'["\']?video["\']?\s*[:=]\s*true', re.IGNORECASE
)
PUBLIC_SCREENSHOTS_PATTERN = re.compile(
    r'(?:screenshotsFolder|videosFolder|downloadsFolder)\s*[:=]\s*'
    r'["\']?(?:/tmp|/var/www|public/|dist/|\.next/)',
    re.IGNORECASE,
)
FILE_SERVER_OUTSIDE_PATTERN = re.compile(
    r'["\']?fileServerFolder["\']?\s*[:=]\s*["\']?\.\./',
    re.IGNORECASE,
)
SUPPORT_FILE_EVAL_PATTERN = re.compile(
    r'["\']?supportFile["\']?\s*[:=].*eval',
    re.IGNORECASE,
)
EXPERIMENTAL_MEMORY_PATTERN = re.compile(
    r'["\']?experimentalMemoryManagement["\']?\s*[:=]\s*false', re.IGNORECASE
)
HOSTS_BYPASS_PATTERN = re.compile(
    r'["\']?hosts["\']?\s*:\s*\{[^}]*\*',
    re.IGNORECASE,
)
JSON_ENV_SECRET_PATTERN = re.compile(
    r'["\']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|'
    r'private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)["\']?\s*:\s*'
    r'["\'][^"\']+["\']',
    re.IGNORECASE,
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
    is_env_file: bool = False
    env_keys: list[str] = field(default_factory=list)


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
    if name.endswith(".json"):
        return "json"
    if name.endswith((".ts", ".mts")):
        return "typescript"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class CypressAnalyzer:
    """Audit Cypress E2E configuration for security and CI risks.

    Scans cypress.config.*, cypress.json, and cypress.env.json for
    chromeWebSecurity disabled, secrets in env files, insecure baseUrl,
    video/screenshot leaks to public paths, and dangerous support files.
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
        for name in ENV_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("cypress.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        for env_path in sorted(self.root.rglob("cypress.env.json")):
            if env_path.is_file() and env_path not in found:
                found.append(env_path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CypressFinding],
        info: CypressInfo,
        is_env_file: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if re.search(r'["\']?baseUrl["\']?\s*[:=]', stripped, re.IGNORECASE):
            for value in _extract_string_literals(stripped):
                if value:
                    info.base_url = value

        env_key_match = re.search(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*:', stripped)
        if env_key_match and is_env_file:
            key = env_key_match.group(1)
            if key not in info.env_keys:
                info.env_keys.append(key)

        if is_env_file and JSON_ENV_SECRET_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="env_secret",
                    severity="high",
                    message="secret value in cypress.env.json — use CI secrets instead of committed env files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            return

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

        if INSECURE_HTTP_PATTERN.search(line) and not is_env_file:
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
                    message="curl|sh pattern in Cypress config — avoid piping remote scripts",
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
                    message="eval in Cypress config — avoid dynamic code execution",
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
                    message="modifyObstructiveCode enabled — may mask XSS and security issues",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_BASE_URL_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="insecure_base_url",
                    severity="high",
                    message="baseUrl uses cleartext HTTP against remote host — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VIDEO_ALWAYS_ON_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="video_always_on",
                    severity="medium",
                    message="video: true records all runs — may leak sensitive UI in CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PUBLIC_SCREENSHOTS_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="public_artifact_dir",
                    severity="high",
                    message="screenshot/video folder may be publicly accessible — use private CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FILE_SERVER_OUTSIDE_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="file_server_outside",
                    severity="high",
                    message="fileServerFolder escapes project root — review for path traversal",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUPPORT_FILE_EVAL_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="support_file_eval",
                    severity="high",
                    message="supportFile references eval — avoid dynamic code in support layer",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HOSTS_BYPASS_PATTERN.search(line):
            findings.append(
                CypressFinding(
                    kind="hosts_bypass",
                    severity="medium",
                    message="hosts map may bypass DNS security controls — review wildcard entries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[CypressFinding], CypressInfo]:
        findings: list[CypressFinding] = []
        rel = str(path.relative_to(self.root))
        is_env_file = path.name == "cypress.env.json"
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, CypressInfo(
                path=rel, file_kind=_file_kind(path), is_env_file=is_env_file
            )

        info = CypressInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
            is_env_file=is_env_file,
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(
                raw.rstrip(), lineno, rel, findings, info, is_env_file
            )

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
import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: process.env.CYPRESS_BASE_URL || 'http://localhost:3000',
    chromeWebSecurity: true,
    video: false,
    screenshotOnRunFailure: true,
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',
    supportFile: 'cypress/support/e2e.ts',
    specPattern: 'cypress/e2e/**/*.cy.{js,ts}',
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
            env_note = " (env file)" if info.is_env_file else ""
            lines.append(f"  - {info.path}{env_note}: baseUrl={base}, env_keys={len(info.env_keys)}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
