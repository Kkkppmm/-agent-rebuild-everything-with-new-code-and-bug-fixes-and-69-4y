"""VitestAnalyzer — audit Vitest and Vite test configuration for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

VITEST_CONFIG_GLOBS = (
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mts",
    "vitest.config.cts",
    "vitest.workspace.ts",
    "vitest.workspace.js",
    "vitest.workspace.mts",
    "vitest.workspace.cts",
)
VITE_CONFIG_NAMES = ("vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.cts")
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
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
SENSITIVE_ENV_PATTERN = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PRIVATE[_-]?KEY|AUTH|"
    r"AWS_|GITHUB_TOKEN|NPM_TOKEN|DATABASE_URL|CONNECTION_STRING)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
REMOTE_SETUP_PATTERN = re.compile(
    r"setupFiles\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
ENV_BLOCK_PATTERN = re.compile(r"^\s*\"?env\"?\s*[:=]", re.IGNORECASE)
SETUP_BLOCK_PATTERN = re.compile(r"^\s*\"?(?:setupFiles|globalSetup)\"?\s*[:=]", re.IGNORECASE)
SERVER_BLOCK_PATTERN = re.compile(r"^\s*\"?(?:server|preview)\"?\s*[:=]", re.IGNORECASE)
TEST_BLOCK_PATTERN = re.compile(r"^\s*\"?test\"?\s*[:=]", re.IGNORECASE)


@dataclass
class VitestFinding:
    """A security or best-practice issue in a Vitest configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class VitestInfo:
    """Parsed metadata about a Vitest configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    environments: list[str] = field(default_factory=list)
    setup_files: list[str] = field(default_factory=list)
    has_browser: bool = False
    has_coverage: bool = False


@dataclass
class VitestStats:
    """Aggregate Vitest analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vitest_file(path: Path) -> bool:
    """Return True if the path looks like a Vitest configuration file."""
    return path.name in VITEST_CONFIG_GLOBS


def _is_vite_config(path: Path) -> bool:
    return path.name in VITE_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("vitest.workspace"):
        return "workspace"
    if name.startswith("vitest.config"):
        return "config"
    if name.startswith("vite.config"):
        return "vite"
    return "config"


def _extract_string_literals(line: str) -> list[str]:
    """Return quoted string values from a config line."""
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


def _looks_like_vitest_project(root: Path) -> bool:
    if any((root / name).is_file() for name in VITEST_CONFIG_GLOBS):
        return True
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict) and "vitest" in deps:
                return True
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for value in scripts.values():
                if isinstance(value, str) and "vitest" in value:
                    return True
    for path in root.rglob("vite.config.*"):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"\btest\s*:\s*\{", text):
                return True
    return False


class VitestAnalyzer:
    """Audit Vitest configuration for security and CI risks.

    Scans vitest.config.*, vitest.workspace.*, and vite.config.* files with
    test blocks for hardcoded secrets, disabled filesystem sandboxing, exposed
    browser hosts, remote setup files, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitestFinding] | None = None
        self._stats: VitestStats | None = None
        self._infos: list[VitestInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Vitest configuration paths found in the project."""
        if not _looks_like_vitest_project(self.root):
            return []

        found: list[Path] = []
        for name in VITEST_CONFIG_GLOBS:
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("vitest.config.*", "vitest.workspace.*"):
            for path in sorted(self.root.rglob(pattern.split("*")[0] + "*")):
                if path.is_file() and _is_vitest_file(path) and path not in found:
                    found.append(path)

        for name in VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and path not in found:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if re.search(r"\btest\s*:\s*\{", text):
                    found.append(path)

        for path in sorted(self.root.rglob("vite.config.*")):
            if path.is_file() and path not in found and _is_vite_config(path):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if re.search(r"\btest\s*:\s*\{", text):
                    found.append(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[VitestFinding],
        info: VitestInfo,
        *,
        in_env: bool = False,
        in_setup: bool = False,
        in_server: bool = False,
        in_test: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        for value in _extract_string_literals(stripped):
            if re.search(r"\benvironment\b", stripped, re.IGNORECASE) and value not in info.environments:
                info.environments.append(value)

            if in_setup and value not in info.setup_files:
                info.setup_files.append(value)

            if in_setup and value.startswith(("http://", "https://")):
                findings.append(
                    VitestFinding(
                        kind="remote_setup_file",
                        severity="high",
                        message="remote setupFiles/globalSetup URL — load setup from the repo, not over the network",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_env and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    VitestFinding(
                        kind="sensitive_env",
                        severity="high",
                        message="sensitive env var name in test env block — use process.env and CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(value):
                findings.append(
                    VitestFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive file path in Vitest config — avoid loading secrets into test workers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Vitest config — use env vars and CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Vitest config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL — use HTTPS for proxies, setup files, and API fixtures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(
            r"(?:fs\s*\.\s*strict|server\s*\.\s*fs\s*\.\s*strict|^\s*strict)\s*:\s*false",
            stripped,
            re.IGNORECASE,
        ):
            findings.append(
                VitestFinding(
                    kind="fs_strict_disabled",
                    severity="high",
                    message="filesystem sandbox disabled — keep server.fs.strict enabled to block path traversal",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"allow\s*:\s*\[[^\]]*(?:\.\.|/etc|/root)", stripped, re.IGNORECASE):
            findings.append(
                VitestFinding(
                    kind="fs_allow_traversal",
                    severity="high",
                    message="server.fs.allow includes parent or system paths — restrict Vite filesystem access",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"dangerouslyIgnoreUnhandledErrors\s*:\s*true", stripped, re.IGNORECASE):
            findings.append(
                VitestFinding(
                    kind="ignore_unhandled_errors",
                    severity="medium",
                    message="dangerouslyIgnoreUnhandledErrors enabled — unhandled rejections may hide security regressions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"(?:host|browser\s*\.\s*host)\s*:\s*true", stripped, re.IGNORECASE):
            findings.append(
                VitestFinding(
                    kind="exposed_host",
                    severity="medium",
                    message="browser/server host exposed to network — bind to localhost in CI and local dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bbrowser\s*:\s*\{", stripped, re.IGNORECASE):
            info.has_browser = True

        if re.search(r"\bcoverage\s*:\s*\{", stripped, re.IGNORECASE):
            info.has_coverage = True

        if re.search(r"proxy\s*:\s*\{[^\}]*http://", stripped, re.IGNORECASE):
            findings.append(
                VitestFinding(
                    kind="insecure_proxy",
                    severity="medium",
                    message="insecure HTTP proxy in Vitest/Vite config — use HTTPS upstream targets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in config — avoid remote code execution patterns",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Vitest config — review scripts and globalSetup hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_SETUP_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="remote_setup_file",
                    severity="high",
                    message="remote setupFiles URL — vendor setup scripts in the repository",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_test and re.search(r"passWithNoTests\s*:\s*false", stripped, re.IGNORECASE):
            findings.append(
                VitestFinding(
                    kind="pass_with_no_tests_disabled",
                    severity="low",
                    message="passWithNoTests disabled — CI may fail silently when test discovery breaks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[VitestFinding], VitestInfo]:
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return [], VitestInfo(path=rel, file_kind=_file_kind(path))

        findings: list[VitestFinding] = []
        info = VitestInfo(path=rel, lines=len(lines), file_kind=_file_kind(path))

        in_env = False
        in_setup = False
        in_server = False
        in_test = False
        brace_depth = 0

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            if TEST_BLOCK_PATTERN.match(stripped):
                in_test = True
            if ENV_BLOCK_PATTERN.match(stripped):
                in_env = True
            if SETUP_BLOCK_PATTERN.match(stripped):
                in_setup = True
            if SERVER_BLOCK_PATTERN.match(stripped):
                in_server = True

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_env=in_env,
                in_setup=in_setup,
                in_server=in_server,
                in_test=in_test,
            )

            brace_depth += stripped.count("{") - stripped.count("}")
            if brace_depth <= 0:
                in_env = False
                in_setup = False
                in_server = False
                in_test = False
                brace_depth = 0

        return findings, info

    def analyze(self) -> list[VitestFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VitestFinding] = []
        infos: list[VitestInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = VitestStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VitestStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VitestInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened vitest.config.ts snippet with secure defaults."""
        return """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    passWithNoTests: true,
    dangerouslyIgnoreUnhandledErrors: false,
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
  },
  server: {
    fs: {
      strict: true,
      allow: [process.cwd()],
    },
  },
});
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Vitest configs: none found"
        return (
            f"Vitest configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Vitest analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            envs = ", ".join(info.environments[:6]) if info.environments else "none"
            setup = ", ".join(info.setup_files[:4]) if info.setup_files else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"env={envs}, setup={setup}, browser={info.has_browser}, coverage={info.has_coverage}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
