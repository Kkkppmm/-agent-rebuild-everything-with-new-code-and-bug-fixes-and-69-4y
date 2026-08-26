"""VitestAnalyzer — audit Vitest config and setup files for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

VITEST_CONFIG_NAMES = (
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mjs",
    "vitest.config.cjs",
    "vitest.workspace.ts",
    "vitest.workspace.js",
    "vitest.workspace.mjs",
    "vitest.workspace.cjs",
)
VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.cjs",
)
SETUP_FILE_NAMES = (
    "vitest.setup.ts",
    "vitest.setup.js",
    "vitest.setup.mjs",
    "vitest.setup.cjs",
    "setupTests.ts",
    "setupTests.js",
    "setupTests.mjs",
    "setupTests.cjs",
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
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
REMOTE_IMPORT_PATTERN = re.compile(
    r"(?:import|require)\s*\(?\s*[\"']https?://",
    re.IGNORECASE,
)
IGNORE_ERRORS_PATTERN = re.compile(
    r"dangerouslyIgnoreUnhandledErrors\s*:\s*true\b", re.IGNORECASE
)
ISOLATE_DISABLED_PATTERN = re.compile(r"isolate\s*:\s*false\b", re.IGNORECASE)
TEST_TIMEOUT_ZERO_PATTERN = re.compile(r"testTimeout\s*:\s*0\b", re.IGNORECASE)
PASS_WITH_NO_TESTS_PATTERN = re.compile(r"passWithNoTests\s*:\s*true\b", re.IGNORECASE)
BROWSER_HEADLESS_FALSE_PATTERN = re.compile(
    r"(?:headless|headlessMode)\s*:\s*false\b", re.IGNORECASE
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)\s*:\s*"
    r"['\"][^'\"${][^'\"]*['\"]",
    re.IGNORECASE,
)
FS_ALLOW_ALL_PATTERN = re.compile(
    r"fs\s*:\s*\{[^}]*allow\s*:\s*\[[^\]]*[\"']/?[\"']",
    re.IGNORECASE,
)
COVERAGE_THRESHOLD_ZERO_PATTERN = re.compile(
    r"(?:lines|functions|branches|statements)\s*:\s*0\b", re.IGNORECASE
)
COVERAGE_DISABLED_PATTERN = re.compile(
    r"coverage\s*:\s*\{[^}]*enabled\s*:\s*false\b", re.IGNORECASE
)
REPORTER_HTML_OPEN_PATTERN = re.compile(
    r"reporter\s*:\s*\[[^\]]*[\"']html[\"']", re.IGNORECASE
)
SINGLE_THREAD_PATTERN = re.compile(
    r"(?:fileParallelism|maxConcurrency)\s*:\s*(?:false|0)\b", re.IGNORECASE
)
INSECURE_POOL_PATTERN = re.compile(
    r"poolOptions\s*:\s*\{[^}]*singleFork\s*:\s*true\b", re.IGNORECASE
)
TEST_BLOCK_PATTERN = re.compile(r"\btest\s*:\s*\{", re.IGNORECASE)


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
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class VitestInfo:
    """Parsed metadata about a Vitest configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    setup_files: list[str] = field(default_factory=list)
    reporters: list[str] = field(default_factory=list)
    environments: list[str] = field(default_factory=list)


@dataclass
class VitestStats:
    """Aggregate Vitest analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vitest_config(path: Path) -> bool:
    name = path.name
    if name in VITEST_CONFIG_NAMES or name in SETUP_FILE_NAMES:
        return True
    if name in VITE_CONFIG_NAMES:
        return True
    if name.startswith("vitest.config.") or name.startswith("vitest.workspace."):
        return True
    if name in ("setupTests.ts", "setupTests.js") or name.startswith("vitest.setup."):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in VITEST_CONFIG_NAMES or name.startswith("vitest.config."):
        return "vitest_config"
    if name in VITE_CONFIG_NAMES or name.startswith("vite.config."):
        return "vite_config"
    if name.startswith("vitest.workspace."):
        return "workspace"
    if name in SETUP_FILE_NAMES or name.startswith("vitest.setup.") or name.startswith("setupTests."):
        return "setup"
    return "unknown"


def _looks_like_vitest_project(root: Path) -> bool:
    for name in VITEST_CONFIG_NAMES:
        if (root / name).is_file():
            return True
    for pattern in ("vitest.config.*", "vitest.workspace.*", "vitest.setup.*", "setupTests.*"):
        if any(root.rglob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {
                **(data.get("dependencies") or {}),
                **(data.get("devDependencies") or {}),
            }
            if "vitest" in deps:
                return True
            scripts = data.get("scripts") or {}
            if any("vitest" in str(v) for v in scripts.values()):
                return True
        except (OSError, json.JSONDecodeError):
            pass
    for name in VITE_CONFIG_NAMES:
        path = root / name
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                if TEST_BLOCK_PATTERN.search(text):
                    return True
            except OSError:
                pass
    return False


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class VitestAnalyzer:
    """Audit Vitest configuration and setup files for security and CI risks.

    Scans vitest.config.*, vitest.workspace.*, vite.config.* test blocks, and
    setup files for hardcoded secrets, disabled isolation, browser headless
    misconfiguration, coverage bypass, dangerous setup scripts, and CI pitfalls.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitestFinding] | None = None
        self._stats: VitestStats | None = None
        self._infos: list[VitestInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Vitest-related configuration paths found in the project."""
        if not _looks_like_vitest_project(self.root):
            return []

        found: list[Path] = []
        for name in (*VITEST_CONFIG_NAMES, *VITE_CONFIG_NAMES, *SETUP_FILE_NAMES):
            path = self.root / name
            if path.is_file() and path not in found:
                found.append(path)

        for pattern in (
            "vitest.config.*",
            "vitest.workspace.*",
            "vitest.setup.*",
            "setupTests.*",
            "vite.config.*",
            "**/test/setup.*",
            "**/tests/setup.*",
        ):
            for path in sorted(self.root.rglob(pattern)):
                if not path.is_file() or path in found:
                    continue
                if _is_vitest_config(path):
                    found.append(path)
                elif path.name.startswith("setup") and "test" in str(path.parent).lower():
                    found.append(path)

        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data.get("vitest"), dict):
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[VitestFinding],
        info: VitestInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for value in _extract_string_literals(stripped):
            if "setup" in value.lower() and value not in info.setup_files:
                info.setup_files.append(value)
            if value in ("html", "json", "junit", "verbose", "dot", "tap"):
                if value not in info.reporters:
                    info.reporters.append(value)
            if value in ("node", "jsdom", "happy-dom", "edge-runtime"):
                if value not in info.environments:
                    info.environments.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Vitest config — use env vars or CI secret stores",
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
                    message="AWS access key in Vitest config — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Vitest config — use HTTPS for remote imports and fixtures",
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
                    message="credentials embedded in repository URL — use token env vars or SSH keys",
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
                    message="curl/wget piped to shell in Vitest setup — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous command in Vitest config or setup — review before CI execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line) and info.file_kind in ("setup", "vitest_config", "vite_config"):
            findings.append(
                VitestFinding(
                    kind="eval_in_setup",
                    severity="high",
                    message="eval() in Vitest setup — avoid dynamic code execution in test bootstrap",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_IMPORT_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="remote_import",
                    severity="high",
                    message="remote HTTP import in Vitest config — vendor dependencies locally",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ERRORS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="ignore_unhandled_errors",
                    severity="medium",
                    message="dangerouslyIgnoreUnhandledErrors enabled — unhandled rejections may hide failures in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ISOLATE_DISABLED_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="isolation_disabled",
                    severity="medium",
                    message="test isolation disabled — increases cross-test pollution and flaky CI risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TEST_TIMEOUT_ZERO_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="test_timeout_disabled",
                    severity="medium",
                    message="testTimeout set to 0 — hung tests can block CI indefinitely",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROWSER_HEADLESS_FALSE_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="browser_not_headless",
                    severity="medium",
                    message="browser headless disabled — gate behind CI env or use headless in pipelines",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_SECRET_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="env_secret_exposure",
                    severity="high",
                    message="secret-like value in Vitest env/define block — use process.env with CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FS_ALLOW_ALL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="fs_allow_root",
                    severity="medium",
                    message="server.fs.allow includes filesystem root — restrict to project directories",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COVERAGE_THRESHOLD_ZERO_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="coverage_threshold_zero",
                    severity="low",
                    message="coverage threshold set to 0 — enforce minimum coverage in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COVERAGE_DISABLED_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="coverage_disabled",
                    severity="low",
                    message="coverage explicitly disabled — enable in CI to catch untested regressions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORTER_HTML_OPEN_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="html_reporter",
                    severity="low",
                    message="HTML reporter enabled — ensure reports are not published with sensitive test output",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SINGLE_THREAD_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="parallelism_disabled",
                    severity="low",
                    message="file parallelism or concurrency disabled — may hide race conditions in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_POOL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="single_fork_pool",
                    severity="low",
                    message="singleFork pool option enabled — review for test isolation side effects",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PASS_WITH_NO_TESTS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="pass_with_no_tests",
                    severity="low",
                    message="passWithNoTests enabled — CI may pass when test files are missing",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_package_json(
        self, path: Path, rel: str
    ) -> tuple[list[VitestFinding], VitestInfo]:
        findings: list[VitestFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, VitestInfo(path=rel, file_kind="package")

        raw_lines = text.splitlines()
        info = VitestInfo(path=rel, lines=len(raw_lines), file_kind="package")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                VitestFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="package.json is not valid JSON — fix syntax before running Vitest",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        vitest_block = data.get("vitest", {})
        if isinstance(vitest_block, dict):
            setup_files = vitest_block.get("setupFiles", [])
            if isinstance(setup_files, list):
                info.setup_files.extend(str(s) for s in setup_files)
            env_block = vitest_block.get("env", {})
            if isinstance(env_block, dict):
                for key, value in env_block.items():
                    if re.search(
                        r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)",
                        str(key),
                        re.IGNORECASE,
                    ) and value and not str(value).startswith("${"):
                        findings.append(
                            VitestFinding(
                                kind="env_secret_exposure",
                                severity="high",
                                message=f"secret-like env var {key} in package.json vitest config — use CI secrets",
                                path=rel,
                                lineno=1,
                                line=f"{key}={value}",
                            )
                        )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[VitestFinding], VitestInfo]:
        findings: list[VitestFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, VitestInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = VitestInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        if info.file_kind == "vite_config" and not TEST_BLOCK_PATTERN.search(text):
            return findings, info

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[VitestFinding], VitestInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "package.json":
            return self._analyze_package_json(path, rel)
        return self._analyze_text_file(path, rel)

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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VitestInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold hardened Vitest configuration defaults."""
        return """\
// vitest.config.ts — hardened defaults
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    isolate: true,
    testTimeout: 10_000,
    passWithNoTests: false,
    dangerouslyIgnoreUnhandledErrors: false,
    reporters: ['default', 'junit'],
    outputFile: { junit: './reports/vitest-junit.xml' },
    coverage: {
      enabled: true,
      provider: 'v8',
      reporter: ['text', 'lcov'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 70,
        statements: 80,
      },
    },
    // Load secrets from process.env in setupFiles, not inline env blocks:
  },
  server: {
    fs: {
      allow: ['.'],
    },
  },
});
"""

    def summary(self) -> str:
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
        self.analyze()
        stats = self.stats
        lines = [
            "Vitest analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            setup = ", ".join(info.setup_files[:8]) if info.setup_files else "none"
            reporters = ", ".join(info.reporters[:8]) if info.reporters else "none"
            envs = ", ".join(info.environments[:8]) if info.environments else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.setup_files)} setup file(s)"
            )
            lines.append(f"    setup files: {setup}")
            lines.append(f"    reporters: {reporters}")
            lines.append(f"    environments: {envs}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
