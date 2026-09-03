"""PlaywrightAnalyzer — audit Playwright E2E config for security and CI risks."""

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
IGNORE_HTTPS_PATTERN = re.compile(
    r'["\']?ignoreHTTPSErrors["\']?\s*[:=]\s*true', re.IGNORECASE
)
NO_SANDBOX_PATTERN = re.compile(
    r"(?:--no-sandbox|--disable-setuid-sandbox|--disable-web-security|"
    r"--disable-features=IsolateOrigins)",
    re.IGNORECASE,
)
REMOTE_DEBUG_PATTERN = re.compile(
    r"(?:--remote-debugging-port|--inspect(?:-brk)?=0\.0\.0\.0|"
    r"PWDEBUG\s*[=:]\s*1|debug\s*:\s*true)",
    re.IGNORECASE,
)
BYPASS_CSP_PATTERN = re.compile(
    r'["\']?bypassCSP["\']?\s*[:=]\s*true', re.IGNORECASE
)
ARTIFACT_LEAK_PATTERN = re.compile(
    r"(?:screenshots|videos|traces|outputDir|trace)\s*[:=].*"
    r"(?:/tmp|/var/tmp|/dev/shm|C:\\\\Temp|/public/)",
    re.IGNORECASE,
)
STORAGE_STATE_OUTSIDE_PATTERN = re.compile(
    r'(?:storageState|storage-state)\s*[:=].*(?:\.\./|/etc/|\.ssh/)',
    re.IGNORECASE,
)
WEB_SERVER_DANGEROUS_PATTERN = re.compile(
    r'webServer\s*:\s*\{[^}]*(?:command|url)\s*[:=]',
    re.IGNORECASE,
)
HEADED_CI_PATTERN = re.compile(
    r'["\']?headless["\']?\s*[:=]\s*false', re.IGNORECASE
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
    browsers: list[str] = field(default_factory=list)
    has_web_server: bool = False


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

    Scans playwright.config.* and package.json playwright blocks for TLS bypass,
    disabled sandbox, remote debug bindings, artifact leaks, hardcoded secrets,
    insecure baseURL, dangerous webServer commands, and storageState paths
    outside the project root.
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
                if isinstance(data, dict) and "playwright" in data:
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

        base_match = re.search(r'["\']?baseURL["\']?\s*[:=]', stripped, re.IGNORECASE)
        if base_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.base_url = value

        if re.search(r'["\']?webServer["\']?\s*[:=]', stripped, re.IGNORECASE):
            info.has_web_server = True

        browser_match = re.search(
            r'(?:projects|browsers)\s*[:=]|name\s*:\s*["\'](?:chromium|firefox|webkit)',
            stripped,
            re.IGNORECASE,
        )
        if browser_match:
            for value in _extract_string_literals(stripped):
                if value.lower() in ("chromium", "firefox", "webkit", "chrome", "msedge"):
                    if value not in info.browsers:
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
                    message="curl|sh pattern in Playwright config — avoid piping remote scripts in webServer",
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
                    message="dangerous shell command in Playwright config or webServer",
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

        if IGNORE_HTTPS_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="tls_bypass",
                    severity="high",
                    message="ignoreHTTPSErrors enabled — TLS certificate validation disabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_SANDBOX_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="sandbox_disabled",
                    severity="high",
                    message="browser sandbox or web security disabled — review launch args",
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
                    message="remote debug binding enabled — may expose browser debugger on all interfaces",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BYPASS_CSP_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="csp_bypass",
                    severity="medium",
                    message="bypassCSP enabled — content security policy checks disabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ARTIFACT_LEAK_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="artifact_leak",
                    severity="medium",
                    message="screenshots/videos/traces written to world-readable path — use CI artifacts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STORAGE_STATE_OUTSIDE_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="storage_state_outside",
                    severity="high",
                    message="storageState path outside project — may load credentials from sensitive locations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WEB_SERVER_DANGEROUS_PATTERN.search(line) and DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                PlaywrightFinding(
                    kind="webserver_dangerous",
                    severity="high",
                    message="webServer command contains dangerous shell patterns",
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
                    message="headless: false — headed browsers in CI are slower and may require display server",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?trace["\']?\s*[:=]\s*["\']?on["\']?', stripped, re.IGNORECASE):
            findings.append(
                PlaywrightFinding(
                    kind="trace_always_on",
                    severity="low",
                    message="trace: on captures full traces for every test — consider on-first-retry in CI",
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
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    ignoreHTTPSErrors: false,
    bypassCSP: false,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
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
                f"  - {info.path}: baseURL={base}, browsers={len(info.browsers)}, "
                f"webServer={info.has_web_server}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
