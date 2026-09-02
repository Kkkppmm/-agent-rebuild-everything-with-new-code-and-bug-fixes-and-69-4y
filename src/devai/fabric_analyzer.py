"""FabricAnalyzer — audit fabfile.py for Fabric SSH deployment security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("fabfile.py",)
FAB_PACKAGE_NAMES = ("fabfile/__init__.py",)

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
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
INSECURE_PIP_INDEX_PATTERN = re.compile(
    r"(?:--index-url|--extra-index-url|--trusted-host)\s*[\"']?http://|"
    r"(?:--index-url|--extra-index-url)\s*[\"']http://",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
WARN_ONLY_PATTERN = re.compile(
    r"warn_only\s*=\s*True\b",
    re.IGNORECASE,
)
PROMPT_PATTERN = re.compile(
    r"prompt\s*=\s*False\b",
    re.IGNORECASE,
)
PTY_PATTERN = re.compile(
    r"pty\s*=\s*True\b",
    re.IGNORECASE,
)
ENV_FORWARD_PATTERN = re.compile(
    r"(?:config\.run\.env|run\.env)\s*=\s*(?:os\.environ|dict\(os\.environ\))",
    re.IGNORECASE,
)
CHDIR_OUTSIDE_PATTERN = re.compile(
    r"(?:cd\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/)|"
    r"chdir\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/))",
    re.IGNORECASE,
)
TASK_DECORATOR_PATTERN = re.compile(r"^\s*@task\b")
TASK_DEF_PATTERN = re.compile(r"^\s*def\s+(\w+)\s*\(\s*(?:c|context|conn)\b")
DISABLE_KNOWN_HOSTS_PATTERN = re.compile(
    r"disable_known_hosts\s*=\s*True\b",
    re.IGNORECASE,
)
CONNECT_KWARGS_PASSWORD_PATTERN = re.compile(
    r"connect_kwargs\s*=\s*\{[^}]*[\"']password[\"']\s*:\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
AGENT_FORWARD_PATTERN = re.compile(
    r"(?:forward_agent|agent_forward)\s*=\s*True\b",
    re.IGNORECASE,
)
STRICT_HOST_KEY_CHECKING_OFF_PATTERN = re.compile(
    r"StrictHostKeyChecking\s*[=:]\s*[\"']?(?:no|off|false)[\"']?",
    re.IGNORECASE,
)
USER_PASS_HOST_PATTERN = re.compile(
    r"[\"'][a-zA-Z0-9._-]+:[^@\"'\s]+@[^\"'\s]+[\"']",
    re.IGNORECASE,
)
GATEWAY_PASSWORD_PATTERN = re.compile(
    r"gateway\s*=\s*[\"'][^\"']*:[^@\"']+@",
    re.IGNORECASE,
)
INSECURE_KEY_PATH_PATTERN = re.compile(
    r"key_filename\s*=\s*[\"'](?:/tmp/|\.\./|~/)",
    re.IGNORECASE,
)
REMOTE_ROOT_PATTERN = re.compile(
    r"(?:conn\.run|run)\s*\(\s*[\"']sudo\s",
    re.IGNORECASE,
)


@dataclass
class FabricFinding:
    """A security or best-practice issue in a Fabric fabfile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class FabricInfo:
    """Parsed metadata about a Fabric fabfile."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)


@dataclass
class FabricStats:
    """Aggregate Fabric analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class FabricAnalyzer:
    """Audit fabfile.py for Fabric SSH deployment security risks.

    Scans fabfile.py and fabfile/__init__.py for hardcoded secrets, SSH password
    auth, disabled host key checking, agent forwarding, gateway credentials,
    sudo on remote hosts, warn_only=True, prompt=False, and dangerous shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FabricFinding] | None = None
        self._stats: FabricStats | None = None
        self._infos: list[FabricInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Fabric fabfile paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES + FAB_PACKAGE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[FabricFinding],
        info: FabricInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        task_match = TASK_DEF_PATTERN.match(stripped)
        if task_match:
            task_name = task_match.group(1)
            if task_name not in info.tasks:
                info.tasks.append(task_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get", line, re.IGNORECASE):
                findings.append(
                    FabricFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in fabfile — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in fabfile — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in fabfile — use HTTPS for remote endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if USER_PASS_HOST_PATTERN.search(line) or GATEWAY_PASSWORD_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="ssh_password_auth",
                    severity="high",
                    message="SSH password embedded in host string — use key-based auth and env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CONNECT_KWARGS_PASSWORD_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="connect_kwargs_password",
                    severity="high",
                    message="connect_kwargs contains hardcoded password — use SSH keys or agent",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in fabfile — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in fabfile — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHDIR_OUTSIDE_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="chdir_outside",
                    severity="high",
                    message="cd/chdir points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_KNOWN_HOSTS_PATTERN.search(line) or STRICT_HOST_KEY_CHECKING_OFF_PATTERN.search(
            line
        ):
            findings.append(
                FabricFinding(
                    kind="host_key_checking_disabled",
                    severity="high",
                    message="SSH host key checking disabled — vulnerable to MITM attacks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_ROOT_PATTERN.search(line) or (
            SUDO_PATTERN.search(line) and ("run(" in line or "conn.run" in line)
        ):
            findings.append(
                FabricFinding(
                    kind="remote_sudo",
                    severity="medium",
                    message="remote task runs with sudo — prefer least-privilege deploy users",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WARN_ONLY_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="warn_only",
                    severity="medium",
                    message="warn_only=True masks command failures — prefer explicit error handling",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROMPT_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="prompt_disabled",
                    severity="medium",
                    message="prompt=False disables confirmation for destructive remote commands",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_FORWARD_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="env_forward_all",
                    severity="medium",
                    message="forwarding full os.environ into tasks — prefer explicit env keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PIP_INDEX_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in fabfile tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AGENT_FORWARD_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="agent_forward",
                    severity="medium",
                    message="SSH agent forwarding enabled — can expose local keys on remote hosts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_KEY_PATH_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="insecure_key_path",
                    severity="medium",
                    message="SSH key path outside trusted locations — use ~/.ssh with strict permissions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PTY_PATTERN.search(line):
            findings.append(
                FabricFinding(
                    kind="pty_enabled",
                    severity="low",
                    message="pty=True allocates a pseudo-terminal — review for interactive credential prompts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[FabricFinding], FabricInfo]:
        findings: list[FabricFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, FabricInfo(path=rel)

        info = FabricInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[FabricFinding]:
        """Scan Fabric fabfiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FabricFinding] = []
        infos: list[FabricInfo] = []
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
        self._stats = FabricStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FabricStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FabricInfo]:
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
        """Scaffold a hardened fabfile.py template."""
        return """\
# Generated by DevAI FabricAnalyzer
from __future__ import annotations

import os

from fabric import Connection, task


@task
def deploy(c):
    \"\"\"Deploy to remote host using SSH key auth and env-based credentials.\"\"\"
    host = os.environ.get("DEPLOY_HOST")
    user = os.environ.get("DEPLOY_USER", "deploy")
    if not host:
        raise RuntimeError("DEPLOY_HOST is required")

    conn = Connection(
        host=f"{user}@{host}",
        connect_kwargs={"key_filename": os.path.expanduser("~/.ssh/id_ed25519")},
    )
    conn.run("git pull && systemctl restart app", pty=False, warn_only=False)


@task
def status(c):
    \"\"\"Check remote service status.\"\"\"
    host = os.environ.get("DEPLOY_HOST")
    user = os.environ.get("DEPLOY_USER", "deploy")
    if not host:
        raise RuntimeError("DEPLOY_HOST is required")

    conn = Connection(
        host=f"{user}@{host}",
        connect_kwargs={"key_filename": os.path.expanduser("~/.ssh/id_ed25519")},
    )
    conn.run("systemctl status app", pty=False, warn_only=False)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Fabric configs: none found"
        return (
            f"Fabric configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Fabric analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks) if info.tasks else "none detected"
            lines.append(f"  - {info.path}: tasks={tasks}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
