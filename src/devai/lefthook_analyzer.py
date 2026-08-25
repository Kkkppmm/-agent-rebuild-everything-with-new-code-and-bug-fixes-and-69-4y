"""LefthookAnalyzer — audit lefthook git hook configs for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

LEFTHOOK_NAMES = (
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
    "lefthook-local.yml",
    "lefthook-local.yaml",
)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+.*--force", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\s+", re.IGNORECASE)
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
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*=\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example|\.local)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
REMOTE_EXTEND_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(https?://|git@)",
    re.IGNORECASE,
)
REMOTE_GIT_URL_PATTERN = re.compile(r"^\s*url\s*:\s*['\"]?(https?://|git@)", re.IGNORECASE)
MUTABLE_REF_PATTERN = re.compile(
    r"^\s*ref\s*:\s*(main|master|HEAD|develop|dev|latest)\s*$",
    re.IGNORECASE,
)
RUN_COMMAND_PATTERN = re.compile(r"^\s*run\s*:\s*(.+)$", re.IGNORECASE)
SCRIPT_ENTRY_PATTERN = re.compile(r"^\s{2,}([a-zA-Z0-9#@:_./-]+)\s*:\s*$")
HOOK_GROUP_PATTERN = re.compile(
    r"^\s*(pre-commit|pre-push|commit-msg|prepare-commit-msg|post-commit|"
    r"post-checkout|post-merge|post-rewrite)\s*:\s*$",
    re.IGNORECASE,
)
COMMANDS_BLOCK_PATTERN = re.compile(r"^\s*commands\s*:\s*$", re.IGNORECASE)
SCRIPTS_BLOCK_PATTERN = re.compile(r"^\s*scripts\s*:\s*$", re.IGNORECASE)
EXTENDS_BLOCK_PATTERN = re.compile(r"^\s*extends\s*:\s*$", re.IGNORECASE)
REMOTE_BLOCK_PATTERN = re.compile(r"^\s*remote\s*:\s*$", re.IGNORECASE)
ENV_BLOCK_PATTERN = re.compile(r"^\s*env\s*:\s*$", re.IGNORECASE)


@dataclass
class LefthookFinding:
    """A security or best-practice issue in a lefthook config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LefthookInfo:
    """Parsed metadata about a lefthook config file."""

    path: str
    hooks: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    extends: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class LefthookStats:
    """Aggregate lefthook config analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_lefthook_config(path: Path) -> bool:
    name = path.name
    if name in LEFTHOOK_NAMES:
        return True
    lower = name.lower()
    return lower.startswith("lefthook") and lower.endswith((".yml", ".yaml"))


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class LefthookAnalyzer:
    """Audit lefthook git hook configs for security risks and best practices.

    Scans lefthook.yml, lefthook.yaml, and lefthook-local.* for curl-pipe-to-shell,
    destructive rm -rf, sudo usage, secrets in env blocks, chmod 777, git force-push,
    eval usage, remote extends, mutable remote git refs, and sensitive path references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LefthookFinding] | None = None
        self._stats: LefthookStats | None = None
        self._infos: list[LefthookInfo] | None = None

    def configs(self) -> list[Path]:
        """Return lefthook config paths found in the project."""
        found: list[Path] = []
        for name in LEFTHOOK_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yml")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yaml")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[LefthookFinding],
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        line: str,
    ) -> None:
        findings.append(
            LefthookFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=line.strip(),
            )
        )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LefthookFinding],
        info: LefthookInfo,
        *,
        in_extends: bool,
        in_remote: bool,
        in_env: bool,
        current_hook: str | None,
        current_command: str | None,
    ) -> tuple[bool, bool, bool, str | None, str | None]:
        stripped = _strip_comment(line)
        if not stripped:
            return in_extends, in_remote, in_env, current_hook, current_command

        hook_match = HOOK_GROUP_PATTERN.match(stripped)
        if hook_match:
            hook = hook_match.group(1).lower()
            if hook not in info.hooks:
                info.hooks.append(hook)
            return False, False, False, hook, None

        if EXTENDS_BLOCK_PATTERN.match(stripped):
            return True, False, False, current_hook, None
        if REMOTE_BLOCK_PATTERN.match(stripped):
            return False, True, False, current_hook, None
        if ENV_BLOCK_PATTERN.match(stripped):
            return False, False, True, current_hook, current_command
        if COMMANDS_BLOCK_PATTERN.match(stripped) or SCRIPTS_BLOCK_PATTERN.match(stripped):
            return False, False, False, current_hook, None

        if in_extends and stripped.startswith("-"):
            entry = stripped.lstrip("- ").strip().strip("'\"")
            info.extends.append(entry)
            if REMOTE_EXTEND_PATTERN.match(stripped):
                self._add_finding(
                    findings,
                    "remote_extend",
                    "high",
                    "remote extends from URL/git — pin to a commit SHA or vendor locally",
                    rel,
                    lineno,
                    line,
                )
            return in_extends, in_remote, in_env, current_hook, current_command

        if in_remote:
            if REMOTE_GIT_URL_PATTERN.match(stripped):
                if stripped.lower().startswith("url:") and "http://" in stripped.lower():
                    self._add_finding(
                        findings,
                        "insecure_http",
                        "medium",
                        "remote git URL uses insecure HTTP",
                        rel,
                        lineno,
                        line,
                    )
            if MUTABLE_REF_PATTERN.match(stripped):
                self._add_finding(
                    findings,
                    "mutable_remote_ref",
                    "medium",
                    "remote git ref is mutable (main/master/HEAD) — pin to a commit SHA",
                    rel,
                    lineno,
                    line,
                )

        if in_env and ":" in stripped and not stripped.endswith(":"):
            key = stripped.split(":", 1)[0].strip()
            if key:
                info.env_keys.append(key)
            if SECRET_VAR_PATTERN.search(stripped):
                self._add_finding(
                    findings,
                    "hardcoded_secret",
                    "high",
                    "possible secret or credential in env block",
                    rel,
                    lineno,
                    line,
                )
            if AWS_ACCESS_KEY_PATTERN.search(stripped):
                self._add_finding(
                    findings,
                    "aws_access_key",
                    "high",
                    "possible AWS access key in env block",
                    rel,
                    lineno,
                    line,
                )

        if current_hook and stripped.endswith(":"):
            indent = len(line) - len(line.lstrip())
            entry_name = stripped.rstrip(":").strip()
            if indent >= 4 and entry_name and entry_name not in {
                "commands",
                "scripts",
                "env",
                "parallel",
                "skip",
                "glob",
                "exclude",
                "stage_fixed",
                "runner",
                "git",
            }:
                if entry_name not in info.commands:
                    info.commands.append(entry_name)

        script_match = SCRIPT_ENTRY_PATTERN.match(stripped)
        if script_match and current_hook:
            script_name = script_match.group(1)
            if script_name not in info.scripts:
                info.scripts.append(script_name)

        command_match = None
        if stripped and not stripped.endswith(":") and current_hook:
            indent = len(line) - len(line.lstrip())
            if indent >= 4 and ":" not in stripped:
                command_match = stripped

        run_match = RUN_COMMAND_PATTERN.match(stripped)
        command_text = run_match.group(1).strip() if run_match else command_match
        if command_text:
            checks = [
                (
                    CURL_PIPE_SHELL_PATTERN,
                    "curl_pipe_shell",
                    "high",
                    "piping curl/wget to shell is unsafe",
                ),
                (
                    RM_RF_ROOT_PATTERN,
                    "destructive_rm",
                    "high",
                    "destructive rm -rf on root or home",
                ),
                (SUDO_PATTERN, "sudo_usage", "medium", "sudo in hook command"),
                (CHMOD_777_PATTERN, "chmod_777", "high", "chmod 777 grants world-writable permissions"),
                (FORCE_PUSH_PATTERN, "force_push", "high", "git push --force in hook command"),
                (EVAL_PATTERN, "eval_usage", "high", "eval in hook command"),
                (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in hook command"),
                (SCM_CREDENTIALS_PATTERN, "scm_credentials", "high", "credentials embedded in SCM URL"),
                (TLS_VERIFY_OFF_PATTERN, "tls_verify_disabled", "high", "TLS verification disabled"),
                (DANGEROUS_SHELL_PATTERN, "dangerous_shell", "high", "dangerous shell pattern in hook command"),
                (SENSITIVE_PATH_PATTERN, "sensitive_path", "medium", "references sensitive credential path"),
            ]
            for pattern, kind, severity, message in checks:
                if pattern.search(command_text):
                    self._add_finding(
                        findings,
                        kind,
                        severity,
                        message,
                        rel,
                        lineno,
                        line,
                    )

        return in_extends, in_remote, in_env, current_hook, current_command

    def _analyze_file(self, path: Path) -> tuple[list[LefthookFinding], LefthookInfo]:
        findings: list[LefthookFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, LefthookInfo(path=rel)

        info = LefthookInfo(path=rel, lines=len(raw_lines))
        in_extends = False
        in_remote = False
        in_env = False
        current_hook: str | None = None
        current_command: str | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            in_extends, in_remote, in_env, current_hook, current_command = self._scan_line(
                raw,
                lineno,
                rel,
                findings,
                info,
                in_extends=in_extends,
                in_remote=in_remote,
                in_env=in_env,
                current_hook=current_hook,
                current_command=current_command,
            )

        return findings, info

    def analyze(self) -> list[LefthookFinding]:
        """Scan lefthook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LefthookFinding] = []
        infos: list[LefthookInfo] = []
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
        self._stats = LefthookStats(
            configs=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> LefthookStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[LefthookInfo]:
        """Return parsed lefthook metadata."""
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened lefthook config template."""
        return """\
# Generated by DevAI LefthookAnalyzer
pre-commit:
  parallel: true
  commands:
    lint:
      run: ruff check src tests
      glob: "*.py"

    test:
      run: python -m pytest -q

# Use CI secrets or local env files — never hardcode tokens in env blocks
# env:
#   API_TOKEN: ${API_TOKEN}

# Avoid curl | sh — vendor scripts with checksum verification
# Avoid sudo, chmod 777, and git push --force in hook commands
# Pin remote extends and remote.git.ref to commit SHAs — avoid main/master/HEAD
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Lefthook configs: none found"
        return (
            f"Lefthook configs: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Lefthook analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            hooks = ", ".join(info.hooks[:8]) if info.hooks else "none"
            lines.append(
                f"  - {info.path}: {len(info.hooks)} hook(s), "
                f"{len(info.commands)} command(s), {len(info.scripts)} script(s)"
            )
            lines.append(f"    hooks: {hooks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
