"""TurboAnalyzer — audit turbo.json and turbo.jsonc for security and cache safety."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

TURBO_CONFIG_NAMES = ("turbo.json", "turbo.jsonc")
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
DISABLE_SIGNATURE_PATTERN = re.compile(
    r"(?:dangerouslyDisableSignature|disableSignature|signature)\s*[=:]\s*(?:true|false)",
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
ENV_ARRAY_PATTERN = re.compile(
    r"^\s*\"?(?:globalEnv|globalPassThroughEnv|env|passThroughEnv)\"?\s*[:=]",
    re.IGNORECASE,
)
DEPENDENCY_ARRAY_PATTERN = re.compile(
    r"^\s*\"?(?:globalDependencies|inputs)\"?\s*[:=]",
    re.IGNORECASE,
)
TASK_PATTERN = re.compile(r"^\s*\"([a-zA-Z0-9#@:_-]+)\"\s*:\s*\{", re.IGNORECASE)


@dataclass
class TurboFinding:
    """A security or best-practice issue in a Turborepo configuration file."""

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
class TurboInfo:
    """Parsed metadata about a Turborepo configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    tasks: list[str] = field(default_factory=list)
    global_env: list[str] = field(default_factory=list)
    global_pass_through: list[str] = field(default_factory=list)
    global_dependencies: list[str] = field(default_factory=list)


@dataclass
class TurboStats:
    """Aggregate Turborepo analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_turbo_file(path: Path) -> bool:
    """Return True if the path looks like a Turborepo configuration file."""
    return path.name in TURBO_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    if path.name == "turbo.jsonc":
        return "jsonc"
    return "json"


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC for parsing."""
    result: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            i = end
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def _extract_string_literals(line: str) -> list[str]:
    """Return quoted string values from a config line."""
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', line)


class TurboAnalyzer:
    """Audit Turborepo configuration for security and cache safety.

    Scans turbo.json and turbo.jsonc for hardcoded secrets, insecure remote
    cache URLs, sensitive env vars in globalPassThroughEnv, disabled cache
    signatures, sensitive file inputs, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TurboFinding] | None = None
        self._stats: TurboStats | None = None
        self._infos: list[TurboInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Turborepo configuration paths found in the project."""
        found: list[Path] = []
        for name in TURBO_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("turbo.json*")):
            if path.is_file() and path not in found and _is_turbo_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TurboFinding],
        info: TurboInfo,
        *,
        in_global_env: bool = False,
        in_global_pass_through: bool = False,
        in_global_deps: bool = False,
        in_task_env: bool = False,
        in_task_pass_through: bool = False,
        in_task_inputs: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        for value in _extract_string_literals(stripped):
            if TASK_PATTERN.match(stripped) and value not in info.tasks:
                info.tasks.append(value)

            if in_global_env and value not in info.global_env:
                info.global_env.append(value)
            if in_global_pass_through and value not in info.global_pass_through:
                info.global_pass_through.append(value)
            if in_global_deps and value not in info.global_dependencies:
                info.global_dependencies.append(value)

            if SENSITIVE_PATH_PATTERN.search(value):
                findings.append(
                    TurboFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive file path in turbo config — exclude secrets from cache inputs and dependencies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_global_pass_through and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    TurboFinding(
                        kind="global_pass_through_secret",
                        severity="high",
                        message="sensitive env var in globalPassThroughEnv — may leak secrets across all tasks and remote cache",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_task_pass_through and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    TurboFinding(
                        kind="task_pass_through_secret",
                        severity="medium",
                        message="sensitive env var in passThroughEnv — verify it is not cached or logged",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_global_env and SENSITIVE_ENV_PATTERN.search(value):
                findings.append(
                    TurboFinding(
                        kind="global_env_secret",
                        severity="medium",
                        message="sensitive env var in globalEnv — ensure it is hashed into cache keys and not logged",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_task_inputs and SENSITIVE_PATH_PATTERN.search(value):
                findings.append(
                    TurboFinding(
                        kind="task_sensitive_input",
                        severity="high",
                        message="sensitive file in task inputs — may embed secrets in remote cache artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                TurboFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in turbo config — use CI secrets and env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TurboFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in turbo config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TurboFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL — use HTTPS for remote cache and team endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                TurboFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'"?dangerouslyDisableSignature"?\s*:\s*true', stripped, re.IGNORECASE):
            findings.append(
                TurboFinding(
                    kind="disabled_signature",
                    severity="high",
                    message="dangerouslyDisableSignature enabled — remote cache artifacts are not verified",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'"signature"\s*:\s*false', stripped, re.IGNORECASE):
            findings.append(
                TurboFinding(
                    kind="disabled_signature",
                    severity="high",
                    message="remote cache signature verification disabled — enable signature checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                TurboFinding(
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
                TurboFinding(
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
                TurboFinding(
                    kind="cache_disabled",
                    severity="low",
                    message="task caching disabled — verify this is intentional for sensitive tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TurboFinding], TurboInfo]:
        findings: list[TurboFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, TurboInfo(path=rel, file_kind=_file_kind(path))

        info = TurboInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        in_global_env = False
        in_global_pass_through = False
        in_global_deps = False
        in_task_env = False
        in_task_pass_through = False
        in_task_inputs = False
        array_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            task_match = TASK_PATTERN.match(stripped)
            if task_match and task_match.group(1) not in info.tasks:
                info.tasks.append(task_match.group(1))

            if re.match(r'^\s*"globalEnv"\s*:', stripped, re.IGNORECASE):
                in_global_env = True
                in_global_pass_through = False
                in_global_deps = False
                in_task_env = False
                in_task_pass_through = False
                in_task_inputs = False
                array_indent = len(line) - len(line.lstrip())

            elif re.match(r'^\s*"globalPassThroughEnv"\s*:', stripped, re.IGNORECASE):
                in_global_pass_through = True
                in_global_env = False
                in_global_deps = False
                in_task_env = False
                in_task_pass_through = False
                in_task_inputs = False
                array_indent = len(line) - len(line.lstrip())

            elif re.match(r'^\s*"globalDependencies"\s*:', stripped, re.IGNORECASE):
                in_global_deps = True
                in_global_env = False
                in_global_pass_through = False
                in_task_env = False
                in_task_pass_through = False
                in_task_inputs = False
                array_indent = len(line) - len(line.lstrip())

            elif re.match(r'^\s*"env"\s*:', stripped, re.IGNORECASE):
                in_task_env = True
                in_task_pass_through = False
                in_task_inputs = False
                in_global_env = False
                in_global_pass_through = False
                in_global_deps = False
                array_indent = len(line) - len(line.lstrip())

            elif re.match(r'^\s*"passThroughEnv"\s*:', stripped, re.IGNORECASE):
                in_task_pass_through = True
                in_task_env = False
                in_task_inputs = False
                in_global_env = False
                in_global_pass_through = False
                in_global_deps = False
                array_indent = len(line) - len(line.lstrip())

            elif re.match(r'^\s*"inputs"\s*:', stripped, re.IGNORECASE):
                in_task_inputs = True
                in_task_env = False
                in_task_pass_through = False
                in_global_env = False
                in_global_pass_through = False
                in_global_deps = False
                array_indent = len(line) - len(line.lstrip())

            current_indent = len(line) - len(line.lstrip())
            if current_indent <= array_indent and stripped in ("}", "],"):
                in_global_env = False
                in_global_pass_through = False
                in_global_deps = False
                in_task_env = False
                in_task_pass_through = False
                in_task_inputs = False

            if stripped in ("}", "],") and current_indent <= array_indent:
                in_global_env = False
                in_global_pass_through = False
                in_global_deps = False
                in_task_env = False
                in_task_pass_through = False
                in_task_inputs = False

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_global_env=in_global_env,
                in_global_pass_through=in_global_pass_through,
                in_global_deps=in_global_deps,
                in_task_env=in_task_env,
                in_task_pass_through=in_task_pass_through,
                in_task_inputs=in_task_inputs,
            )

        try:
            parsed = json.loads(_strip_jsonc_comments(raw_text))
            if isinstance(parsed, dict):
                remote_cache = parsed.get("remoteCache")
                if isinstance(remote_cache, dict):
                    if remote_cache.get("signature") is False:
                        findings.append(
                            TurboFinding(
                                kind="disabled_signature",
                                severity="high",
                                message="remote cache signature verification disabled — enable signature checks",
                                path=rel,
                                lineno=1,
                                line="remoteCache.signature: false",
                            )
                        )
                    if remote_cache.get("dangerouslyDisableSignature") is True:
                        findings.append(
                            TurboFinding(
                                kind="disabled_signature",
                                severity="high",
                                message="dangerouslyDisableSignature enabled — remote cache artifacts are not verified",
                                path=rel,
                                lineno=1,
                                line="remoteCache.dangerouslyDisableSignature: true",
                            )
                        )
                    team_id = remote_cache.get("teamId") or remote_cache.get("team")
                    if isinstance(team_id, str) and HARDCODED_SECRET_PATTERN.search(team_id):
                        findings.append(
                            TurboFinding(
                                kind="hardcoded_secret",
                                severity="medium",
                                message="suspicious value in remoteCache team config — verify no secrets are committed",
                                path=rel,
                                lineno=1,
                                line=f"remoteCache team: {team_id}",
                            )
                        )
        except json.JSONDecodeError:
            findings.append(
                TurboFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="turbo config is not valid JSON/JSONC — fix syntax before relying on cache settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TurboFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TurboFinding] = []
        infos: list[TurboInfo] = []
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
        self._stats = TurboStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TurboStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TurboInfo]:
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
        """Scaffold a hardened turbo.json snippet with secure defaults."""
        return """\
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": [".env.example"],
  "globalEnv": ["NODE_ENV"],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["src/**", "package.json"],
      "outputs": ["dist/**"],
      "env": ["NODE_ENV"]
    },
    "test": {
      "dependsOn": ["build"],
      "cache": true
    }
  },
  "remoteCache": {
    "signature": true
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Turbo configs: none found"
        return (
            f"Turbo configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Turbo analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            envs = ", ".join(info.global_env[:6]) if info.global_env else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.tasks)} task(s), globalEnv={envs}, tasks={tasks}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
