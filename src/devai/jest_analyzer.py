"""JestAnalyzer — audit Jest configuration for security and CI risks."""

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
    "jest.config.jsx",
    "jest.config.tsx",
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
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
GLOBAL_SECRET_PATTERN = re.compile(
    r'["\']?globals["\']?\s*:.*(?:api[_-]?key|secret|token|password|credential)',
    re.IGNORECASE,
)
PATH_TRAVERSAL_MAPPER_PATTERN = re.compile(
    r'["\']?\^?[^"\']*["\']?\s*:\s*["\'][^"\']*\.\./',
    re.IGNORECASE,
)
UNPINNED_GIT_PRESET_PATTERN = re.compile(
    r'["\']?preset["\']?\s*:\s*["\'](?:git\+|github:|gitlab:|bitbucket:)[^"\']*'
    r"(?:#|:)(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
REMOTE_RESULTS_PROCESSOR_PATTERN = re.compile(
    r'["\']?testResultsProcessor["\']?\s*:.*(?:https?://|fetch\s*\(|axios)',
    re.IGNORECASE,
)
INSECURE_TEST_URL_PATTERN = re.compile(
    r'["\']?testURL["\']?\s*:\s*["\']http://(?!localhost|127\.0\.0\.1)',
    re.IGNORECASE,
)
EXPOSE_ENV_PATTERN = re.compile(
    r'["\']?(?:setupFiles|setupFilesAfterEnv)["\']?\s*:.*process\.env',
    re.IGNORECASE,
)
DISABLE_SNAPSHOT_SERIALIZER_PATTERN = re.compile(
    r'["\']?snapshotSerializers["\']?\s*:.*eval',
    re.IGNORECASE,
)
WILDCARD_TRANSFORM_IGNORE_PATTERN = re.compile(
    r'["\']?transformIgnorePatterns["\']?\s*:\s*\[[^\]]*["\']<rootDir>/node_modules/?["\']',
    re.IGNORECASE,
)
HIGH_TEST_TIMEOUT_PATTERN = re.compile(
    r'["\']?testTimeout["\']?\s*:\s*(?:\d{6,}|[1-9]\d{5,})',
    re.IGNORECASE,
)
CUSTOM_ENVIRONMENT_PATTERN = re.compile(
    r'["\']?testEnvironment["\']?\s*:\s*["\'][^"\']*(?:\.\./|/tmp/|/dev/)',
    re.IGNORECASE,
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
    test_environment: str = ""
    setup_files: list[str] = field(default_factory=list)
    presets: list[str] = field(default_factory=list)
    reporters: list[str] = field(default_factory=list)


@dataclass
class JestStats:
    """Aggregate Jest analysis statistics."""

    configs: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith("jest.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "package.json":
        return "package_json"
    if name.endswith(".json"):
        return "json"
    if name.endswith((".ts", ".tsx")):
        return "typescript"
    if name.endswith((".js", ".cjs", ".mjs", ".jsx")):
        return "javascript"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


def _looks_like_jest_project(root: Path) -> bool:
    for name in CONFIG_NAMES:
        if (root / name).is_file():
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                if "jest" in data:
                    return True
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                if isinstance(deps, dict) and "jest" in deps:
                    return True
                if isinstance(dev_deps, dict) and "jest" in dev_deps:
                    return True
        except (OSError, json.JSONDecodeError):
            pass
    return False


class JestAnalyzer:
    """Audit Jest configuration for security and CI risks.

    Scans jest.config.* files and package.json jest blocks for hardcoded secrets,
    eval in transforms/setup, insecure testURL, path traversal in moduleNameMapper,
    unpinned git presets, remote testResultsProcessor URLs, and dangerous
    globalSetup/globalTeardown scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JestFinding] | None = None
        self._stats: JestStats | None = None
        self._infos: list[JestInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Jest configuration paths found in the project."""
        if not _looks_like_jest_project(self.root):
            return []

        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("jest.config.*")):
            if path.is_file() and path not in found and _is_config_file(path):
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

        env_match = re.search(r'["\']?testEnvironment["\']?\s*:\s*["\']([^"\']+)', stripped)
        if env_match:
            info.test_environment = env_match.group(1)

        setup_match = re.search(r'["\']?(?:setupFiles|setupFilesAfterEnv)["\']?\s*:', stripped)
        if setup_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.setup_files:
                    info.setup_files.append(value)

        preset_match = re.search(r'["\']?preset["\']?\s*:\s*["\']([^"\']+)', stripped)
        if preset_match:
            preset = preset_match.group(1)
            if preset not in info.presets:
                info.presets.append(preset)

        reporter_match = re.search(r'["\']?reporters["\']?\s*:', stripped)
        if reporter_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.reporters:
                    info.reporters.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Jest config — use env vars or CI secret stores",
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
                    message="AWS access key in Jest config — rotate and use secret stores",
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
                    message="insecure HTTP URL in Jest config — use HTTPS for remote endpoints",
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
                    message="curl|sh pattern in Jest config — avoid piping remote scripts in setup hooks",
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
                    message="dangerous command in Jest config — review setup and lifecycle scripts",
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
                    message="eval() in Jest config — avoid dynamic code execution in transforms or setup",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GLOBAL_SECRET_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="globals_secret",
                    severity="high",
                    message="secret-like value in globals block — avoid exposing credentials to all tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PATH_TRAVERSAL_MAPPER_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="path_traversal_mapper",
                    severity="high",
                    message="moduleNameMapper resolves outside project root — review path aliases",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_RESULTS_PROCESSOR_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="remote_results_processor",
                    severity="high",
                    message="testResultsProcessor may send results to remote URL — verify endpoint and auth",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_TEST_URL_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="insecure_test_url",
                    severity="medium",
                    message="testURL uses cleartext HTTP — use HTTPS or localhost for jsdom URL",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_PRESET_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="unpinned_git_preset",
                    severity="medium",
                    message="Jest preset from unpinned git ref — pin to commit SHA or semver tag",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CUSTOM_ENVIRONMENT_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="custom_environment_path",
                    severity="medium",
                    message="custom testEnvironment path outside project — verify environment module is trusted",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXPOSE_ENV_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="env_in_setup",
                    severity="medium",
                    message="setupFiles reference process.env — ensure secrets are not logged in test output",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_SNAPSHOT_SERIALIZER_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="eval_snapshot_serializer",
                    severity="medium",
                    message="eval in snapshotSerializers — custom serializers should not execute dynamic code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_TRANSFORM_IGNORE_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="broad_transform_ignore",
                    severity="low",
                    message="transformIgnorePatterns may skip all of node_modules — verify ESM transforms still apply",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HIGH_TEST_TIMEOUT_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="high_test_timeout",
                    severity="low",
                    message="very high testTimeout may mask hung tests in CI — consider lower timeout with retries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?bail["\']?\s*:\s*(?:0|false)', stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="bail_disabled",
                    severity="low",
                    message="bail disabled — CI may run all tests after first failure, increasing exposure window",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_content(
        self,
        text: str,
        rel: str,
        findings: list[JestFinding],
        info: JestInfo,
        *,
        from_package: bool = False,
    ) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                JestFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Jest config is not valid JSON — fix syntax before relying on test settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return

        config = data.get("jest", {}) if from_package else data
        if not isinstance(config, dict):
            return

        env = config.get("testEnvironment", "")
        if isinstance(env, str):
            info.test_environment = env

        for key in ("setupFiles", "setupFilesAfterEnv"):
            items = config.get(key, [])
            if isinstance(items, str):
                items = [items]
            if isinstance(items, list):
                for item in items:
                    if str(item) not in info.setup_files:
                        info.setup_files.append(str(item))

        preset = config.get("preset", "")
        if isinstance(preset, str) and preset:
            info.presets.append(preset)

        reporters = config.get("reporters", [])
        if isinstance(reporters, list):
            for rep in reporters:
                if isinstance(rep, str) and rep not in info.reporters:
                    info.reporters.append(rep)

        serialized = json.dumps(config)
        for lineno, raw in enumerate(serialized.splitlines(), start=1):
            self._scan_line(raw, lineno, rel, findings, info)

        if isinstance(preset, str) and UNPINNED_GIT_PRESET_PATTERN.search(preset):
            findings.append(
                JestFinding(
                    kind="unpinned_git_preset",
                    severity="medium",
                    message="Jest preset from unpinned git ref — pin to commit SHA or semver tag",
                    path=rel,
                    lineno=1,
                    line=preset,
                )
            )

        mapper = config.get("moduleNameMapper", {})
        if isinstance(mapper, dict):
            for pattern, target in mapper.items():
                if isinstance(target, str) and "../" in target:
                    findings.append(
                        JestFinding(
                            kind="path_traversal_mapper",
                            severity="high",
                            message=f"moduleNameMapper '{pattern}' resolves outside project root",
                            path=rel,
                            lineno=1,
                            line=f"{pattern} -> {target}",
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
        from_package = path.name == "package.json"

        if from_package or path.suffix == ".json":
            self._analyze_json_content(
                raw_text, rel, findings, info, from_package=from_package
            )
            return findings, info

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def _resolve_setup_path(self, setup_rel: str) -> Path | None:
        """Resolve a Jest setupFiles path relative to project root."""
        cleaned = setup_rel.replace("<rootDir>", ".").strip()
        if cleaned.startswith("./"):
            cleaned = cleaned[2:]
        path = (self.root / cleaned).resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError:
            return None
        return path

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
            for setup_rel in info.setup_files:
                setup_path = self._resolve_setup_path(setup_rel)
                if setup_path and setup_path.is_file():
                    setup_findings, setup_info = self._analyze_file(setup_path)
                    findings.extend(setup_findings)
                    infos.append(setup_info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = JestStats(
            configs=len(paths),
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
        """Scaffold a hardened Jest configuration template."""
        return """\
// Generated by DevAI JestAnalyzer
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  bail: 1,
  testTimeout: 10000,
  // Store secrets via environment variables — never in globals:
  // setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
  transformIgnorePatterns: [
    "/node_modules/(?!(@my-scope)/)",
  ],
  reporters: ["default"],
  // Pin presets to semver tags, not git branches:
  // preset: "jest-preset-node",
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Jest configs: none found"
        return (
            f"Jest configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Jest configuration analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            env = info.test_environment or "default"
            setup = ", ".join(info.setup_files[:6]) if info.setup_files else "none"
            presets = ", ".join(info.presets[:6]) if info.presets else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): env={env}, presets={presets}"
            )
            lines.append(f"    setup files: {setup}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
