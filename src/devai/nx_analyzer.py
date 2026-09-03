"""NxAnalyzer — audit nx.json and project.json for security and cache safety."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

NX_CONFIG_NAMES = ("nx.json",)
PROJECT_CONFIG_NAMES = ("project.json",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|accessToken|"
    r"nxCloudAccessToken)\s*[=:]\s*"
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
    r"credentials\.json|service[--]?account\.json)",
    re.IGNORECASE,
)
SENSITIVE_ENV_PATTERN = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PRIVATE[_-]?KEY|AUTH|"
    r"AWS_|GITHUB_TOKEN|NPM_TOKEN|DATABASE_URL|CONNECTION_STRING|NX_CLOUD)",
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
TARGET_PATTERN = re.compile(r'^\s*"([a-zA-Z0-9#@:_-]+)"\s*:\s*\{', re.IGNORECASE)
INPUT_BLOCK_PATTERN = re.compile(
    r'^\s*"(?:inputs|namedInputs|production|default|sharedGlobals)"\s*:',
    re.IGNORECASE,
)
ENV_BLOCK_PATTERN = re.compile(
    r'^\s*"(?:env|passThroughEnv|runtimeArgs|options)"\s*:',
    re.IGNORECASE,
)


@dataclass
class NxFinding:
    """A security or best-practice issue in an Nx configuration file."""

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
class NxInfo:
    """Parsed metadata about an Nx configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    targets: list[str] = field(default_factory=list)
    named_inputs: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    has_nx_cloud: bool = False


@dataclass
class NxStats:
    """Aggregate Nx analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nx_file(path: Path) -> bool:
    """Return True if the path looks like an Nx configuration file."""
    return path.name in NX_CONFIG_NAMES or path.name in PROJECT_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    if path.name == "nx.json":
        return "workspace"
    if path.name == "project.json":
        return "project"
    return "json"


def _extract_string_literals(line: str) -> list[str]:
    """Return quoted string values from a config line."""
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', line)


class NxAnalyzer:
    """Audit Nx workspace and project configuration for security and cache safety.

    Scans nx.json and project.json for hardcoded secrets, Nx Cloud access tokens,
    sensitive env vars in target options, credential files in inputs/namedInputs,
    insecure HTTP URLs, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NxFinding] | None = None
        self._stats: NxStats | None = None
        self._infos: list[NxInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Nx configuration paths found in the project."""
        found: list[Path] = []
        for name in NX_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("project.json")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NxFinding],
        info: NxInfo,
        *,
        in_inputs: bool = False,
        in_env: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        for value in _extract_string_literals(stripped):
            if TARGET_PATTERN.match(stripped) and value not in info.targets:
                info.targets.append(value)

            if in_inputs and value not in info.named_inputs:
                info.named_inputs.append(value)

            if SENSITIVE_PATH_PATTERN.search(value):
                findings.append(
                    NxFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive file path in Nx inputs — exclude secrets from cache inputs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_env and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    NxFinding(
                        kind="sensitive_env",
                        severity="high",
                        message="sensitive env var in target options — may leak secrets via Nx cache",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Nx config — use CI secrets and env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'"nxCloudAccessToken"\s*:', stripped, re.IGNORECASE):
            if re.search(r':\s*"[^"$][^"]*"', stripped):
                findings.append(
                    NxFinding(
                        kind="nx_cloud_token",
                        severity="high",
                        message="hardcoded nxCloudAccessToken — use NX_CLOUD_ACCESS_TOKEN env var",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            info.has_nx_cloud = True

        if re.search(r'"accessToken"\s*:', stripped, re.IGNORECASE):
            if re.search(r':\s*"[^"$][^"]*"', stripped):
                findings.append(
                    NxFinding(
                        kind="nx_cloud_token",
                        severity="high",
                        message="hardcoded Nx Cloud accessToken — use CI secrets or env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            info.has_nx_cloud = True

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Nx config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL — use HTTPS for Nx Cloud and remote endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in config — avoid piping remote scripts to shell",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                NxFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in config — review for privilege escalation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'"cache"\s*:\s*false', stripped, re.IGNORECASE):
            findings.append(
                NxFinding(
                    kind="cache_disabled",
                    severity="low",
                    message="target caching disabled — verify this is intentional for sensitive tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        plugin_match = re.search(r'"plugin"\s*:\s*"([^"]+)"', stripped, re.IGNORECASE)
        if plugin_match:
            plugin = plugin_match.group(1)
            if plugin not in info.plugins:
                info.plugins.append(plugin)

    def _analyze_file(self, path: Path) -> tuple[list[NxFinding], NxInfo]:
        findings: list[NxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, NxInfo(path=rel, file_kind=_file_kind(path))

        info = NxInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        in_inputs = False
        in_env = False
        block_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            target_match = TARGET_PATTERN.match(stripped)
            if target_match and target_match.group(1) not in info.targets:
                info.targets.append(target_match.group(1))

            if INPUT_BLOCK_PATTERN.match(stripped):
                in_inputs = True
                in_env = False
                block_indent = len(line) - len(line.lstrip())
            elif ENV_BLOCK_PATTERN.match(stripped):
                in_env = True
                in_inputs = False
                block_indent = len(line) - len(line.lstrip())

            current_indent = len(line) - len(line.lstrip())
            if current_indent <= block_indent and stripped in ("}", "],"):
                in_inputs = False
                in_env = False

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_inputs=in_inputs,
                in_env=in_env,
            )

        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                if parsed.get("nxCloudAccessToken"):
                    token = parsed["nxCloudAccessToken"]
                    if isinstance(token, str) and token and not token.startswith("${"):
                        findings.append(
                            NxFinding(
                                kind="nx_cloud_token",
                                severity="high",
                                message="hardcoded nxCloudAccessToken — use NX_CLOUD_ACCESS_TOKEN env var",
                                path=rel,
                                lineno=1,
                                line="nxCloudAccessToken",
                            )
                        )
                    info.has_nx_cloud = True

                runner_opts = parsed.get("tasksRunnerOptions", {})
                if isinstance(runner_opts, dict):
                    for runner_cfg in runner_opts.values():
                        if not isinstance(runner_cfg, dict):
                            continue
                        options = runner_cfg.get("options", {})
                        if isinstance(options, dict) and options.get("accessToken"):
                            token = options["accessToken"]
                            if isinstance(token, str) and token and not token.startswith("${"):
                                findings.append(
                                    NxFinding(
                                        kind="nx_cloud_token",
                                        severity="high",
                                        message="hardcoded Nx Cloud accessToken — use CI secrets or env vars",
                                        path=rel,
                                        lineno=1,
                                        line="tasksRunnerOptions.accessToken",
                                    )
                                )
                            info.has_nx_cloud = True
        except json.JSONDecodeError:
            findings.append(
                NxFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Nx config is not valid JSON — fix syntax before relying on cache settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[NxFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NxFinding] = []
        infos: list[NxInfo] = []
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
        self._stats = NxStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NxStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NxInfo]:
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
        """Scaffold a hardened nx.json snippet with secure defaults."""
        return """\
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": ["{projectRoot}/**/*", "sharedGlobals"],
    "production": ["default", "!{projectRoot}/**/?(*.)+(spec|test).[jt]s?(x)?(.snap)"]
  },
  "targetDefaults": {
    "build": {
      "cache": true,
      "inputs": ["production", "^production"],
      "outputs": ["{projectRoot}/dist"]
    },
    "test": {
      "cache": true,
      "inputs": ["default", "^production"]
    }
  },
  "tasksRunnerOptions": {
    "default": {
      "runner": "nx/tasks-runners/default",
      "options": {
        "cacheableOperations": ["build", "test", "lint"]
      }
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nx configs: none found"
        return (
            f"Nx configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Nx analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            targets = ", ".join(info.targets[:8]) if info.targets else "none"
            inputs = ", ".join(info.named_inputs[:6]) if info.named_inputs else "none"
            cloud = "yes" if info.has_nx_cloud else "no"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.targets)} target(s), inputs={inputs}, nxCloud={cloud}, targets={targets}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
