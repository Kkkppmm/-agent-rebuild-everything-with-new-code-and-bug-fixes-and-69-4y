"""VitestAnalyzer — audit vitest.config.* and Vitest setup for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

VITEST_CONFIG_NAMES = (
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mts",
    "vitest.config.mjs",
    "vitest.config.cjs",
    "vitest.workspace.ts",
    "vitest.workspace.js",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
NPM_TOKEN_PATTERN = re.compile(r"[\"']?npm_[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
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
IGNORE_UNHANDLED_ERRORS_PATTERN = re.compile(
    r"dangerouslyIgnoreUnhandledErrors\s*:\s*true\b",
    re.IGNORECASE,
)
ISOLATE_DISABLED_PATTERN = re.compile(
    r"(?:isolate\s*:\s*false|--no-isolate\b|fileParallelism\s*:\s*false\b)",
    re.IGNORECASE,
)
ALLOW_ONLY_PATTERN = re.compile(
    r"allowOnly\s*:\s*true\b",
    re.IGNORECASE,
)
ZERO_TIMEOUT_PATTERN = re.compile(
    r"testTimeout\s*:\s*0\b|hookTimeout\s*:\s*0\b",
    re.IGNORECASE,
)
BROWSER_ENABLED_PATTERN = re.compile(
    r"browser\s*:\s*\{[^}]*enabled\s*:\s*true",
    re.IGNORECASE | re.DOTALL,
)
REMOTE_SETUP_PATTERN = re.compile(
    r"(?:setupFiles|globalSetup|setupFilesAfterEnv)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
INLINE_ALL_DEPS_PATTERN = re.compile(
    r"deps\s*:\s*\{[^}]*inline\s*:\s*\[\s*[\"']\*[\"']\s*\]",
    re.IGNORECASE | re.DOTALL,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
DISABLED_COVERAGE_THRESHOLD_PATTERN = re.compile(
    r"coverage\s*:\s*\{[^}]*(?:thresholds\s*:\s*\{\s*\}|enabled\s*:\s*false\b)",
    re.IGNORECASE | re.DOTALL,
)
PASS_WITH_NO_TESTS_PATTERN = re.compile(
    r"passWithNoTests\s*:\s*true\b",
    re.IGNORECASE,
)
UNSAFE_ENV_PATTERN = re.compile(
    r"(?:process\.env\.(?:NODE_TLS_REJECT_UNAUTHORIZED|ALLOW_INSECURE))\s*=\s*[\"']?0[\"']?",
    re.IGNORECASE,
)


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
    environments: list[str] = field(default_factory=list)
    setup_files: list[str] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)


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
    return path.name in VITEST_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("vitest.workspace"):
        return "workspace"
    if name.startswith("vitest.config"):
        return "config"
    if name == "package.json":
        return "package"
    if name.startswith("vite.config"):
        return "vite"
    return "unknown"


def _looks_like_vitest_project(root: Path) -> bool:
    if any((root / name).exists() for name in VITEST_CONFIG_NAMES):
        return True
    for pattern in ("vitest.config.*", "vitest.workspace.*"):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            scripts = data.get("scripts", {})
            if isinstance(scripts, dict):
                for script in scripts.values():
                    if isinstance(script, str) and "vitest" in script.lower():
                        return True
            for key in ("devDependencies", "dependencies"):
                block = data.get(key, {})
                if isinstance(block, dict) and any(
                    name.startswith("vitest") or name == "@vitest/ui"
                    for name in block
                ):
                    return True
        except (OSError, json.JSONDecodeError):
            pass
    for vite_name in ("vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs"):
        vite_path = root / vite_name
        if vite_path.is_file():
            try:
                text = vite_path.read_text(encoding="utf-8", errors="replace")
                if "vitest" in text.lower() or "defineConfig" in text:
                    if "test:" in text or "test :" in text:
                        return True
            except OSError:
                pass
    return False


class VitestAnalyzer:
    """Audit Vitest configuration for security and CI reliability risks.

    Scans vitest.config.*, vitest.workspace.*, vite.config.* test blocks, and
    package.json for hardcoded secrets, disabled error handling, missing isolation,
    remote setup files, and dangerous lifecycle hooks.
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
        for name in VITEST_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("vitest.config.*", "vitest.workspace.*"):
            for path in sorted(self.root.rglob(pattern.split("*")[0] + "*")):
                if path.is_file() and path not in found and _is_vitest_file(path):
                    found.append(path)

        for vite_name in ("vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs"):
            path = self.root / vite_name
            if path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    if "test:" in text or "test :" in text:
                        found.append(path)
                except OSError:
                    pass

        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                scripts = data.get("scripts", {})
                dev_deps = data.get("devDependencies", {})
                if isinstance(scripts, dict) and any(
                    isinstance(v, str) and "vitest" in v.lower() for v in scripts.values()
                ):
                    found.append(pkg)
                elif isinstance(dev_deps, dict) and any(
                    name.startswith("vitest") or name == "@vitest/ui" for name in dev_deps
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
        findings: list[VitestFinding],
        info: VitestInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        env_match = re.search(
            r"environment\s*:\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if env_match:
            info.environments.append(env_match.group(1))

        setup_match = re.search(
            r"(?:setupFiles|globalSetup|setupFilesAfterEnv)\s*:\s*\[[^\]]*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if setup_match:
            info.setup_files.append(setup_match.group(1))

        project_match = re.search(
            r"(?:projects|workspace)\s*:\s*\[[^\]]*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if project_match:
            info.projects.append(project_match.group(1))

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

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in Vitest config — use environment variable interpolation",
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
                    message="insecure HTTP URL in Vitest config — use HTTPS for remote setup and fixtures",
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
                    message="curl/wget piped to shell in Vitest config — vendor scripts locally",
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
                    message="dangerous command in Vitest config — review setup and global hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_UNHANDLED_ERRORS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="ignore_unhandled_errors",
                    severity="high",
                    message="dangerouslyIgnoreUnhandledErrors enabled — unhandled rejections may hide failures",
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
                    message="test isolation disabled — shared state can cause flaky or order-dependent tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_ONLY_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="allow_only_enabled",
                    severity="medium",
                    message="allowOnly enabled — .only tests may skip coverage in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ZERO_TIMEOUT_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="zero_timeout",
                    severity="medium",
                    message="zero test/hook timeout — hung tests can block CI indefinitely",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROWSER_ENABLED_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="browser_mode_enabled",
                    severity="low",
                    message="Vitest browser mode enabled — ensure sandboxing and headless CI runners",
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
                    message="remote setup file URL — load setup files from the repository only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INLINE_ALL_DEPS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="inline_all_deps",
                    severity="medium",
                    message="server.deps.inline set to wildcard — may expose unexpected modules to tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_COVERAGE_THRESHOLD_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="coverage_disabled",
                    severity="low",
                    message="coverage thresholds empty or disabled — enforce minimum coverage in CI",
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
                    message="passWithNoTests enabled — CI may succeed when test files are missing",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_ENV_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="unsafe_env_override",
                    severity="high",
                    message="TLS or security env override in Vitest config — keep verification enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="config_eval",
                    severity="high",
                    message="eval in Vitest config — avoid dynamic code execution in test setup",
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
                    message="package.json is not valid JSON — fix syntax before running tests",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for name, script in scripts.items():
                if not isinstance(script, str):
                    continue
                if "vitest" not in script.lower():
                    continue
                info.setup_files.append(name)
                if DANGEROUS_SCRIPT_PATTERN.search(script):
                    findings.append(
                        VitestFinding(
                            kind="dangerous_test_script",
                            severity="high",
                            message=f"dangerous {name} script — review Vitest npm scripts",
                            path=rel,
                            lineno=1,
                            line=script,
                        )
                    )
                if "--allowOnly" in script or "--no-isolate" in script:
                    findings.append(
                        VitestFinding(
                            kind="unsafe_cli_flags",
                            severity="medium",
                            message=f"unsafe Vitest CLI flags in {name} script",
                            path=rel,
                            lineno=1,
                            line=script,
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
        """Scaffold hardened vitest.config.ts defaults."""
        return """\
// vitest.config.ts — hardened defaults for Vitest projects
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    isolate: true,
    testTimeout: 10_000,
    hookTimeout: 10_000,
    passWithNoTests: false,
    allowOnly: false,
    dangerouslyIgnoreUnhandledErrors: false,
    coverage: {
      enabled: true,
      provider: 'v8',
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 70,
        statements: 80,
      },
    },
    // setupFiles: ['./test/setup.ts'],
    // environment: 'node',
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
            envs = ", ".join(info.environments[:8]) if info.environments else "none"
            setups = ", ".join(info.setup_files[:8]) if info.setup_files else "none"
            projects = ", ".join(info.projects[:8]) if info.projects else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.setup_files)} setup ref(s), {len(info.projects)} project(s)"
            )
            lines.append(f"    environments: {envs}")
            lines.append(f"    setup files: {setups}")
            lines.append(f"    projects: {projects}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
