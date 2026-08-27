"""WebdriverIOAnalyzer — audit WebdriverIO wdio.conf.* for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "wdio.conf.js",
    "wdio.conf.ts",
    "wdio.conf.mjs",
    "wdio.conf.cjs",
    "webdriverio.config.js",
    "webdriverio.config.ts",
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
ACCEPT_INSECURE_CERTS_PATTERN = re.compile(
    r'["\']?(?:acceptInsecureCerts|acceptSslCerts)["\']?\s*[:=]\s*true',
    re.IGNORECASE,
)
NO_SANDBOX_PATTERN = re.compile(
    r"(?:--no-sandbox|--disable-web-security|--disable-setuid-sandbox)",
    re.IGNORECASE,
)
REMOTE_DEBUG_PATTERN = re.compile(
    r"(?:--remote-debugging-port|--inspect(?:-brk)?|devtools:\s*true)",
    re.IGNORECASE,
)
SPECS_OUTSIDE_PATTERN = re.compile(
    r"(?:specs?|suites?)\s*[:=].*(?:\.\./|/etc/|\.ssh/)",
    re.IGNORECASE,
)
OUTPUT_DIR_LEAK_PATTERN = re.compile(
    r"(?:outputDir|screenshotPath)\s*[:=].*"
    r"(?:/tmp|/var/tmp|/dev/shm|C:\\\\Temp|/public/)",
    re.IGNORECASE,
)
MAX_INSTANCES_HIGH_PATTERN = re.compile(
    r'["\']?maxInstances["\']?\s*[:=]\s*(\d+)', re.IGNORECASE
)
INSECURE_PROTOCOL_PATTERN = re.compile(
    r'["\']?protocol["\']?\s*[:=]\s*["\']http["\']', re.IGNORECASE
)
SERVICES_CREDENTIALS_PATTERN = re.compile(
    r"(?:services|user|key)\s*[:=].*(?:password|secret|api[_-]?key|token)",
    re.IGNORECASE,
)
HEADLESS_DISABLED_PATTERN = re.compile(
    r'["\']?headless["\']?\s*[:=]\s*false', re.IGNORECASE
)


@dataclass
class WebdriverIOFinding:
    """A security or best-practice issue in a WebdriverIO configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class WebdriverIOInfo:
    """Parsed metadata about a WebdriverIO configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    runner: str = ""
    base_url: str = ""
    max_instances: int | None = None


@dataclass
class WebdriverIOStats:
    """Aggregate WebdriverIO analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith(("wdio.conf.", "webdriverio.config."))


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


class WebdriverIOAnalyzer:
    """Audit WebdriverIO configuration for security and CI risks.

    Scans wdio.conf.* for hardcoded secrets, acceptInsecureCerts, --no-sandbox,
    remote debugging ports, insecure baseUrl/protocol, specs outside the project,
    artifact leaks in outputDir, and excessive maxInstances.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WebdriverIOFinding] | None = None
        self._stats: WebdriverIOStats | None = None
        self._infos: list[WebdriverIOInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return WebdriverIO configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("wdio.conf.*", "webdriverio.config.*"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found:
                    found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    scripts = data.get("scripts", {})
                    if isinstance(scripts, dict) and any(
                        "wdio" in str(v).lower() for v in scripts.values()
                    ):
                        for name in CONFIG_NAMES:
                            p = self.root / name
                            if p.is_file() and p not in found:
                                found.append(p)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[WebdriverIOFinding],
        info: WebdriverIOInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        runner_match = re.search(r'["\']?runner["\']?\s*[:=]', stripped, re.IGNORECASE)
        if runner_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.runner = value

        base_match = re.search(r'["\']?baseUrl["\']?\s*[:=]', stripped, re.IGNORECASE)
        if base_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.base_url = value

        max_match = MAX_INSTANCES_HIGH_PATTERN.search(stripped)
        if max_match:
            info.max_instances = int(max_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in WebdriverIO config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in WebdriverIO config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in WebdriverIO config — use HTTPS for baseUrl and services",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
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
                WebdriverIOFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in WebdriverIO config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in WebdriverIO config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in WebdriverIO config — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ACCEPT_INSECURE_CERTS_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="accept_insecure_certs",
                    severity="high",
                    message="acceptInsecureCerts: true disables TLS verification — enable only in local dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_SANDBOX_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="sandbox_disabled",
                    severity="high",
                    message="browser launched with --no-sandbox or --disable-web-security — review for CI containers only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_DEBUG_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="remote_debug",
                    severity="high",
                    message="remote debugging enabled — may expose browser process to network",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SPECS_OUTSIDE_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="specs_outside_project",
                    severity="high",
                    message="specs/suites path outside project — review for dependency confusion",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OUTPUT_DIR_LEAK_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="artifact_leak",
                    severity="medium",
                    message="outputDir/screenshotPath in shared temp or public directory — artifacts may leak",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PROTOCOL_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="insecure_protocol",
                    severity="high",
                    message="protocol: http for remote WebDriver — use HTTPS for non-local endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SERVICES_CREDENTIALS_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="services_credentials",
                    severity="high",
                    message="credentials in services config — use env vars or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if info.max_instances is not None and info.max_instances > 10:
            findings.append(
                WebdriverIOFinding(
                    kind="max_instances_high",
                    severity="medium",
                    message=f"maxInstances: {info.max_instances} may exhaust CI resources — cap parallel sessions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HEADLESS_DISABLED_PATTERN.search(line):
            findings.append(
                WebdriverIOFinding(
                    kind="headless_disabled",
                    severity="low",
                    message="headless: false requires display server in CI — prefer headless in pipelines",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[WebdriverIOFinding], WebdriverIOInfo]:
        findings: list[WebdriverIOFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, WebdriverIOInfo(path=rel, file_kind=_file_kind(path))

        info = WebdriverIOInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[WebdriverIOFinding]:
        """Scan WebdriverIO configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[WebdriverIOFinding] = []
        infos: list[WebdriverIOInfo] = []
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
        self._stats = WebdriverIOStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> WebdriverIOStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[WebdriverIOInfo]:
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
        """Scaffold a hardened wdio.conf.ts template."""
        return """\
// Generated by DevAI WebdriverIOAnalyzer
import type { Options } from '@wdio/types';

export const config: Options.Testrunner = {
  runner: 'local',
  autoCompileOpts: { autoCompile: true, tsNodeOpts: { project: './tsconfig.json' } },
  specs: ['./test/specs/**/*.ts'],
  maxInstances: 5,
  capabilities: [{
    browserName: 'chrome',
    'goog:chromeOptions': {
      args: ['headless', 'disable-gpu', 'window-size=1280,800'],
    },
  }],
  logLevel: 'warn',
  bail: 1,
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  waitforTimeout: 10000,
  connectionRetryTimeout: 120000,
  connectionRetryCount: 3,
  framework: 'mocha',
  reporters: ['spec'],
  mochaOpts: { ui: 'bdd', timeout: 60000 },
  outputDir: './test-results',
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "WebdriverIO configs: none found"
        return (
            f"WebdriverIO configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "WebdriverIO analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            runner = info.runner or "default"
            lines.append(f"  - {info.path}: runner={runner}, baseUrl={info.base_url or 'unset'}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
