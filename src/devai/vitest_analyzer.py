"""VitestAnalyzer — audit Vitest and Vite test config for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mts",
    "vitest.config.mjs",
    "vitest.config.cjs",
    "vitest.workspace.ts",
    "vitest.workspace.js",
)
VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mts",
    "vite.config.mjs",
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
IGNORE_ERRORS_PATTERN = re.compile(
    r'["\']?dangerouslyIgnoreUnhandledErrors["\']?\s*[:=]\s*true', re.IGNORECASE
)
ALLOW_ONLY_PATTERN = re.compile(
    r'["\']?allowOnly["\']?\s*[:=]\s*true', re.IGNORECASE
)
FS_ALLOW_PARENT_PATTERN = re.compile(
    r'(?:fs\.allow|server\.fs\.allow|["\']?\.\.["\']?)', re.IGNORECASE
)
INSPECT_ALL_PATTERN = re.compile(
    r"(?:--inspect(?:-brk)?=0\.0\.0\.0|execArgv.*inspect)", re.IGNORECASE
)
COVERAGE_EXCLUDE_ALL_PATTERN = re.compile(
    r"coverage\s*:\s*\{[^}]*exclude\s*:\s*\[\s*['\"]?\*\*['\"]?\s*\]",
    re.IGNORECASE,
)
MOCKS_DISABLED_PATTERN = re.compile(
    r"(?:mockReset|restoreMocks|clearMocks)\s*[:=]\s*false", re.IGNORECASE
)
GLOBALS_ENABLED_PATTERN = re.compile(r"globals\s*[:=]\s*true", re.IGNORECASE)
INLINE_DEPS_PATTERN = re.compile(
    r"(?:deps\.inline|server\.deps\.inline)\s*[:=]\s*\[\s*['\"]?\*['\"]?\s*\]",
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
    environment: str = ""
    setup_files: list[str] = field(default_factory=list)


@dataclass
class VitestStats:
    """Aggregate Vitest analysis statistics."""

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


def _looks_like_vitest_project(root: Path) -> bool:
    for name in CONFIG_NAMES + VITE_CONFIG_NAMES:
        if (root / name).is_file():
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                if "vitest" in data:
                    return True
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if any(k in deps for k in ("vitest", "@vitest/ui", "@vitest/coverage-v8")):
                    return True
        except (OSError, json.JSONDecodeError):
            pass
    return False


class VitestAnalyzer:
    """Audit Vitest configuration for security and CI risks.

    Scans vitest.config.*, vite.config.* test blocks, and package.json vitest
    for hardcoded secrets, dangerouslyIgnoreUnhandledErrors, allowOnly in CI,
    server.fs.allow parent traversal, remote inspect bindings, disabled mock
    resets, global test pollution, and inline deps bypassing module resolution.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitestFinding] | None = None
        self._stats: VitestStats | None = None
        self._infos: list[VitestInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Vitest configuration paths found in the project."""
        if not _looks_like_vitest_project(self.root):
            return []

        found: list[Path] = []
        for name in CONFIG_NAMES + VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("vitest.config.*", "vitest.workspace.*", "vite.config.*"):
            for path in sorted(self.root.glob(pattern)):
                if path.is_file() and path not in found:
                    found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "vitest" in data:
                    if pkg not in found:
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

        env_match = re.search(r'["\']?environment["\']?\s*[:=]', stripped, re.IGNORECASE)
        if env_match:
            for value in _extract_string_literals(stripped):
                if value:
                    info.environment = value

        setup_match = re.search(r'["\']?setupFiles["\']?\s*[:=]', stripped, re.IGNORECASE)
        if setup_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.setup_files:
                    info.setup_files.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Vitest config — use env vars or CI secrets",
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
                    message="insecure HTTP URL in Vitest config — use HTTPS for plugins and proxies",
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
                    message="credentials embedded in URL — use SSH keys or secret stores",
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
                    message="curl|sh pattern in Vitest config — avoid piping remote scripts in setup",
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
                    message="dangerous shell command in Vitest config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Vitest config or setup reference — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_ERRORS_PATTERN.search(line):
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

        if ALLOW_ONLY_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="allow_only_enabled",
                    severity="medium",
                    message="allowOnly enabled — .only tests may ship to CI if not guarded",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FS_ALLOW_PARENT_PATTERN.search(line) and (
            ".." in line or "fs" in line.lower() or "allow" in line.lower()
        ):
            findings.append(
                VitestFinding(
                    kind="fs_parent_traversal",
                    severity="high",
                    message="server.fs.allow includes parent paths — may expose files outside project root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSPECT_ALL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="remote_inspect",
                    severity="high",
                    message="debugger bound to 0.0.0.0 — exposes Node inspector to the network",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COVERAGE_EXCLUDE_ALL_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="coverage_disabled",
                    severity="medium",
                    message="coverage exclude blocks all files — verify CI coverage gates",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MOCKS_DISABLED_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="mocks_not_reset",
                    severity="low",
                    message="mock reset/restore disabled — tests may leak state across files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GLOBALS_ENABLED_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="globals_enabled",
                    severity="low",
                    message="globals: true pollutes global scope — prefer explicit imports from vitest",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INLINE_DEPS_PATTERN.search(line):
            findings.append(
                VitestFinding(
                    kind="inline_all_deps",
                    severity="medium",
                    message="deps.inline includes wildcard — may bypass intended module isolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[VitestFinding], VitestInfo]:
        findings: list[VitestFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, VitestInfo(path=rel, file_kind=_file_kind(path))

        info = VitestInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[VitestFinding]:
        """Scan Vitest configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VitestFinding] = []
        infos: list[VitestInfo] = []
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
        self._stats = VitestStats(
            config_files=len(paths),
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
        """Scaffold a hardened Vitest config template."""
        return """\
// Generated by DevAI VitestAnalyzer
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    clearMocks: true,
    mockReset: true,
    restoreMocks: true,
    allowOnly: !process.env.CI,
    dangerouslyIgnoreUnhandledErrors: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      exclude: ["node_modules/", "dist/", "**/*.d.ts"],
    },
    server: {
      deps: {
        inline: [],
      },
    },
  },
  server: {
    fs: {
      allow: ["."],
    },
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Vitest configs: none found"
        return (
            f"Vitest configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Vitest analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            env = info.environment or "default"
            lines.append(f"  - {info.path}: env={env}, setup_files={len(info.setup_files)}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
