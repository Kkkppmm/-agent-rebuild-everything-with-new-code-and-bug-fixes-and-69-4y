"""JestAnalyzer — audit Jest test configuration for security and CI risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

JEST_CONFIG_GLOBS = (
    "jest.config.js",
    "jest.config.ts",
    "jest.config.mjs",
    "jest.config.cjs",
    "jest.config.json",
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
SETUP_BLOCK_PATTERN = re.compile(
    r"^\s*\"?(?:setupFiles|setupFilesAfterEnv|globalSetup|globalTeardown)\"?\s*[:=]",
    re.IGNORECASE,
)
GLOBALS_BLOCK_PATTERN = re.compile(r"^\s*\"?globals\"?\s*[:=]", re.IGNORECASE)
ENV_BLOCK_PATTERN = re.compile(r"^\s*\"?(?:testEnvironmentOptions|env)\"?\s*[:=]", re.IGNORECASE)


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
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JestInfo:
    """Parsed metadata about a Jest configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    test_environment: str = ""
    setup_files: list[str] = field(default_factory=list)
    has_coverage: bool = False
    preset: str = ""


@dataclass
class JestStats:
    """Aggregate Jest analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jest_file(path: Path) -> bool:
    """Return True if the path looks like a Jest configuration file."""
    return path.name in JEST_CONFIG_GLOBS or path.name.startswith("jest.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "package.json":
        return "package"
    if name.startswith("jest.config"):
        return "config"
    return "config"


def _extract_string_literals(line: str) -> list[str]:
    """Return quoted string values from a config line."""
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


def _looks_like_jest_project(root: Path) -> bool:
    if any((root / name).is_file() for name in JEST_CONFIG_GLOBS):
        return True
    for path in root.rglob("jest.config.*"):
        if path.is_file():
            return True
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False
        if isinstance(data.get("jest"), dict):
            return True
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict) and "jest" in deps:
                return True
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for value in scripts.values():
                if isinstance(value, str) and re.search(r"\bjest\b", value):
                    return True
    return False


class JestAnalyzer:
    """Audit Jest configuration for security and CI risks.

    Scans jest.config.* and package.json jest blocks for hardcoded secrets,
    remote setup URLs, insecure testURL values, dangerous globalSetup hooks,
    and sensitive path mappings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JestFinding] | None = None
        self._stats: JestStats | None = None
        self._infos: list[JestInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Jest configuration paths found in the project."""
        if not _looks_like_jest_project(self.root):
            return []

        found: list[Path] = []
        for name in JEST_CONFIG_GLOBS:
            path = self.root / name
            if path.is_file():
                found.append(path)

        for path in sorted(self.root.rglob("jest.config.*")):
            if path.is_file() and _is_jest_file(path) and path not in found:
                found.append(path)

        package_json = self.root / "package.json"
        if package_json.is_file():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
            if isinstance(data.get("jest"), dict) and package_json not in found:
                found.append(package_json)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[JestFinding],
        info: JestInfo,
        *,
        in_setup: bool = False,
        in_globals: bool = False,
        in_env: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        for value in _extract_string_literals(stripped):
            if re.search(r"\btestEnvironment\b", stripped, re.IGNORECASE) and value:
                info.test_environment = value

            if re.search(r"\bpreset\b", stripped, re.IGNORECASE) and value:
                info.preset = value

            if in_setup and value not in info.setup_files:
                info.setup_files.append(value)

            if in_setup and value.startswith(("http://", "https://")):
                findings.append(
                    JestFinding(
                        kind="remote_setup_file",
                        severity="high",
                        message="remote setup/global hook URL — load setup from the repo, not over the network",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_globals and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    JestFinding(
                        kind="sensitive_global",
                        severity="high",
                        message="sensitive global in Jest config — use process.env and CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_env and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    JestFinding(
                        kind="sensitive_env",
                        severity="high",
                        message="sensitive env var in testEnvironmentOptions — use process.env and CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if value.startswith("http://") and not value.startswith("http://localhost"):
                if re.search(r"\b(?:preset|extends|testURL|runner|reporters)\b", stripped, re.IGNORECASE):
                    findings.append(
                        JestFinding(
                            kind="insecure_http",
                            severity="high",
                            message="insecure HTTP URL in Jest config — use HTTPS for presets, reporters, and testURL",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if SENSITIVE_PATH_PATTERN.search(value):
                findings.append(
                    JestFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive file path in Jest config — avoid loading secrets into test workers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Jest config — use env vars and CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(
            r'"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL)"\s*:',
            stripped,
            re.IGNORECASE,
        ) and re.search(r":\s*['\"][^\"'\s${}]", stripped):
            findings.append(
                JestFinding(
                    kind="sensitive_global",
                    severity="high",
                    message="sensitive key with literal value in Jest config — use process.env and CI secrets",
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
                    message="AWS access key in Jest config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line) and re.search(
            r"\b(?:testURL|preset|extends|reporters|runner|watchPlugins)\b",
            stripped,
            re.IGNORECASE,
        ):
            findings.append(
                JestFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL — use HTTPS for presets, reporters, and test fixtures",
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
                    message="credentials embedded in URL — use SSH keys or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\btestURL\b.*http://", stripped, re.IGNORECASE) and INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                JestFinding(
                    kind="insecure_test_url",
                    severity="high",
                    message="insecure testURL — use https:// or a local file:// fixture",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bforceExit\s*:\s*true", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="force_exit",
                    severity="medium",
                    message="forceExit enabled — open handles may hide async security regressions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bhaste\s*\.\s*enableSymlinks\s*:\s*true", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="symlinks_enabled",
                    severity="medium",
                    message="haste.enableSymlinks enabled — symlink traversal may bypass module isolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bresetMocks\s*:\s*false", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="reset_mocks_disabled",
                    severity="low",
                    message="resetMocks disabled — mocked secrets may leak between tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bclearMocks\s*:\s*false", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="clear_mocks_disabled",
                    severity="low",
                    message="clearMocks disabled — mock state may leak between tests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bcoverage\b", stripped, re.IGNORECASE) and "{" in stripped:
            info.has_coverage = True

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                JestFinding(
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
                JestFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Jest config — review globalSetup and scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bglobalSetup\b.*https?://", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="remote_global_setup",
                    severity="high",
                    message="remote globalSetup URL — vendor setup scripts in the repository",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bmoduleNameMapper\b.*(?:\.\.|/etc|/root)", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="path_traversal_mapper",
                    severity="high",
                    message="moduleNameMapper includes parent or system paths — restrict module resolution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"\bcacheDirectory\b.*(?:\.ssh|\.aws|credentials)", stripped, re.IGNORECASE):
            findings.append(
                JestFinding(
                    kind="sensitive_cache_dir",
                    severity="medium",
                    message="cacheDirectory points to sensitive location — use a project-local .jest-cache",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_jest(self, data: dict, rel: str) -> tuple[list[JestFinding], JestInfo]:
        """Analyze package.json jest block or jest.config.json."""
        text = json.dumps(data, indent=2)
        lines = text.splitlines()
        findings: list[JestFinding] = []
        info = JestInfo(path=rel, lines=len(lines), file_kind=_file_kind(Path(rel)))

        for lineno, line in enumerate(lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[JestFinding], JestInfo]:
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        if path.name == "package.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return [], JestInfo(path=rel, file_kind="package")
            jest_block = data.get("jest")
            if not isinstance(jest_block, dict):
                return [], JestInfo(path=rel, file_kind="package")
            return self._analyze_json_jest(jest_block, rel)

        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return [], JestInfo(path=rel, file_kind="config")
            return self._analyze_json_jest(data, rel)

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return [], JestInfo(path=rel, file_kind=_file_kind(path))

        findings: list[JestFinding] = []
        info = JestInfo(path=rel, lines=len(lines), file_kind=_file_kind(path))

        in_setup = False
        in_globals = False
        in_env = False
        brace_depth = 0

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            if SETUP_BLOCK_PATTERN.match(stripped):
                in_setup = True
            if GLOBALS_BLOCK_PATTERN.match(stripped):
                in_globals = True
            if ENV_BLOCK_PATTERN.match(stripped):
                in_env = True

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_setup=in_setup,
                in_globals=in_globals,
                in_env=in_env,
            )

            brace_depth += stripped.count("{") - stripped.count("}")
            if brace_depth <= 0:
                in_setup = False
                in_globals = False
                in_env = False
                brace_depth = 0

        return findings, info

    def analyze(self) -> list[JestFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JestFinding] = []
        infos: list[JestInfo] = []
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
        self._stats = JestStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JestStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JestInfo]:
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
        """Scaffold a hardened jest.config.js snippet with secure defaults."""
        return """\
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  setupFilesAfterEnv: ['./test/setup.js'],
  coverageProvider: 'v8',
  collectCoverageFrom: ['src/**/*.{js,ts,tsx}'],
  testURL: 'https://localhost',
  cacheDirectory: '<rootDir>/.jest-cache',
  haste: {
    enableSymlinks: false,
  },
};
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
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
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Jest analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            setup = ", ".join(info.setup_files[:4]) if info.setup_files else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"env={info.test_environment or 'default'}, preset={info.preset or 'none'}, "
                f"setup={setup}, coverage={info.has_coverage}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
