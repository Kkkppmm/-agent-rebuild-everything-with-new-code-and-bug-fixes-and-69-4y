"""PlaywrightAnalyzer — audit Playwright config for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "playwright.config.ts",
    "playwright.config.js",
    "playwright.config.mjs",
    "playwright.config.cjs",
    "playwright.config.mts",
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
IGNORE_HTTPS_ERRORS_PATTERN = re.compile(
    r'["\']?ignoreHTTPSErrors["\']?\s*[:=]\s*true', re.IGNORECASE
)
BYPASS_CSP_PATTERN = re.compile(r'["\']?bypassCSP["\']?\s*[:=]\s*true', re.IGNORECASE)
NO_SANDBOX_PATTERN = re.compile(
    r"(?:--no-sandbox|chromeSandbox\s*[:=]\s*false)", re.IGNORECASE
)
REMOTE_DEBUG_PATTERN = re.compile(
    r"(?:--remote-debugging-address=0\.0\.0\.0|--inspect(?:-brk)?=0\.0\.0\.0)",
    re.IGNORECASE,
)
DEVTOOLS_ENABLED_PATTERN = re.compile(
    r'["\']?devtools["\']?\s*[:=]\s*true', re.IGNORECASE
)
HEADED_CI_PATTERN = re.compile(r'["\']?headed["\']?\s*[:=]\s*true', re.IGNORECASE)
TRACE_ALWAYS_ON_PATTERN = re.compile(
    r'["\']?trace["\']?\s*[:=]\s*["\']on["\']', re.IGNORECASE
)
VIDEO_ALWAYS_ON_PATTERN = re.compile(
    r'["\']?video["\']?\s*[:=]\s*["\']on["\']', re.IGNORECASE
)
STORAGE_STATE_SECRET_PATTERN = re.compile(
    r"storageState\s*[:=].*(?:password|cookie|session|token|credential)",
    re.IGNORECASE,
)
REUSE_REMOTE_SERVER_PATTERN = re.compile(
    r'reuseExistingServer\s*[:=]\s*true.*(?:http://|https://)(?!localhost|127\.0\.0\.1)',
    re.IGNORECASE,
)
DANGEROUS_PERMISSIONS_PATTERN = re.compile(
    r"permissions\s*:\s*\[[^\]]*(?:clipboard-read|clipboard-write|geolocation|"
    r"midi|notifications|payment-handler)",
    re.IGNORECASE,
)
PROXY_CREDENTIALS_PATTERN = re.compile(
    r"proxy\s*:\s*\{[^}]*(?:username|password)\s*:", re.IGNORECASE
)
HAR_ALWAYS_ON_PATTERN = re.compile(
    r'recordHar\s*:\s*\{[^}]*mode\s*:\s*["\']on["\']', re.IGNORECASE
)


@dataclass
class PlaywrightFinding:
    """A security or best-practice issue in a Playwright configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PlaywrightInfo:
    """Parsed metadata about a Playwright configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    base_url: str = ""
    projects: list[str] = field(default_factory=list)
    browsers: list[str] = field(default_factory=list)


@dataclass
class PlaywrightStats:
    """Aggregate Playwright analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith("playwright.config.")


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


class PlaywrightAnalyzer:
    """Audit Playwright configuration for security and CI risks.

    Scans playwright.config.* and package.json for hardcoded secrets,
    ignoreHTTPSErrors, bypassCSP, --no-sandbox, remote debugging bindings,
    always-on trace/video/HAR recording, storageState credential leaks,
    proxy credentials, and dangerous browser permissions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PlaywrightFinding] | None = None
        self._stats: PlaywrightStats | None = None
        self._infos: list[PlaywrightInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Playwright configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("playwright.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    deps = data.get("devDependencies", {})
                    deps.update(data.get("dependencies", {}))
                    if any(
                        k in deps
                        for k in ("@playwright/test", "playwright", "playwright-core")
                    ):
                        found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PlaywrightFinding],
        info: PlaywrightInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        base_url_match = re.search(r'["\']?baseURL["\']?\s*[:=]', stripped, re.IGNORECASE)
        if base_url_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.base_url = value

        project_match = re.search(r'["\']?name["\']?\s*[:=]', stripped, re.IGNORECASE)
        if project_match and "projects" in stripped.lower() or "use:" in stripped.lower():
            for value in _extract_string_literals(stripped):
                if value and value not in info.projects:
                    info.projects.append(value)

        browser_match = re.search(
            r'["\']?(?:browserName|channel)["\']?\s*[:=]', stripped, re.IGNORECASE
        )
        if browser_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.browsers:
                    info.browsers.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Playwright config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Playwright config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Playwright config — use HTTPS for baseURL and webServer",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
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
                PlaywrightFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Playwright config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Playwright config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Playwright config — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_HTTPS_ERRORS_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="ignore_https_errors",
                    severity="high",
                    message="ignoreHTTPSErrors: true disables TLS validation — use only in local dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BYPASS_CSP_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="bypass_csp",
                    severity="high",
                    message="bypassCSP: true disables Content-Security-Policy — review test scope",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_SANDBOX_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="no_sandbox",
                    severity="high",
                    message="browser sandbox disabled — increases blast radius in CI runners",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_DEBUG_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="remote_debug",
                    severity="high",
                    message="remote debugging bound to 0.0.0.0 — exposes browser debugger on the network",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEVTOOLS_ENABLED_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="devtools_enabled",
                    severity="medium",
                    message="devtools: true in config — may expose sensitive page data in CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HEADED_CI_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="headed_mode",
                    severity="low",
                    message="headed: true — use headless mode in CI for speed and isolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRACE_ALWAYS_ON_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="trace_always_on",
                    severity="medium",
                    message="trace: 'on' records all tests — may leak credentials in CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VIDEO_ALWAYS_ON_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="video_always_on",
                    severity="medium",
                    message="video: 'on' records all tests — may leak sensitive UI state in artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STORAGE_STATE_SECRET_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="storage_state_secrets",
                    severity="high",
                    message="storageState may reference credential/session data — use ephemeral auth fixtures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REUSE_REMOTE_SERVER_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="reuse_remote_server",
                    severity="medium",
                    message="reuseExistingServer against non-localhost — tests may hit unintended environments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_PERMISSIONS_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="dangerous_permissions",
                    severity="medium",
                    message="broad browser permissions granted — minimize permission scope in tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROXY_CREDENTIALS_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="proxy_credentials",
                    severity="high",
                    message="proxy credentials in config — use env vars for proxy authentication",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HAR_ALWAYS_ON_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="har_always_on",
                    severity="medium",
                    message="recordHar mode 'on' captures all network traffic — may store secrets in HAR files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[PlaywrightFinding], PlaywrightInfo]:
        findings: list[PlaywrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, PlaywrightInfo(path=rel, file_kind=_file_kind(path))

        info = PlaywrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PlaywrightFinding]:
        """Scan Playwright configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PlaywrightFinding] = []
        infos: list[PlaywrightInfo] = []
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
        self._stats = PlaywrightStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PlaywrightStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PlaywrightInfo]:
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
        """Scaffold a hardened Playwright config template."""
        return """\
// Generated by DevAI PlaywrightAnalyzer
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:3000",
    trace: "on-first-retry",
    video: "on-first-retry",
    screenshot: "only-on-failure",
    ignoreHTTPSErrors: false,
    bypassCSP: false,
    headless: true,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  webServer: {
    command: "npm run start",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Playwright configs: none found"
        return (
            f"Playwright configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Playwright analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            base = info.base_url or "default"
            lines.append(
                f"  - {info.path}: baseURL={base}, projects={len(info.projects)}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
