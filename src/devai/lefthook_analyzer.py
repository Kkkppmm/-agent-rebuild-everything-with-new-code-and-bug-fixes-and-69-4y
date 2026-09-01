"""LefthookAnalyzer — audit lefthook git hook configs for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "lefthook.yml",
    "lefthook.yaml",
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
SECRET_ENV_VALUE_PATTERN = re.compile(
    r"^\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*:\s*"
    r"['\"]?[^'\"$\s{][^'\"]*['\"]?",
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
EXTEND_URL_PATTERN = re.compile(r"^\s*-\s*url:\s*", re.IGNORECASE)
EXTEND_PATH_PATTERN = re.compile(r"^\s*-\s*path:\s*", re.IGNORECASE)
UNPINNED_REF_PATTERN = re.compile(
    r"^\s*ref:\s*(main|master|HEAD|develop|dev|nightly|latest)\s*$",
    re.IGNORECASE,
)
RUN_LINE_PATTERN = re.compile(r"^\s*run:\s*(.+)$", re.IGNORECASE)
ENV_BLOCK_PATTERN = re.compile(r"^\s*env:\s*$", re.IGNORECASE)
SKIP_ALL_PATTERN = re.compile(r"^\s*skip:\s*true\s*$", re.IGNORECASE)
HOOK_KEY_PATTERN = re.compile(
    r"^(pre-commit|pre-push|commit-msg|post-commit|post-checkout|post-merge|"
    r"prepare-commit-msg|post-rewrite|reference-transaction):\s*$",
    re.IGNORECASE,
)
COMMAND_KEY_PATTERN = re.compile(r"^\s{2,}([a-zA-Z0-9#@:_-]+)\s*:\s*$")
SCRIPT_KEY_PATTERN = re.compile(r"^\s{2,}['\"]?[^'\"]+\.(sh|bash|zsh)['\"]?\s*:\s*$", re.IGNORECASE)


@dataclass
class LefthookFinding:
    """A security or best-practice issue in a lefthook config file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LefthookHookInfo:
    """Parsed metadata about a lefthook hook block."""

    name: str
    commands: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    skip_all: bool = False


@dataclass
class LefthookInfo:
    """Parsed metadata about a lefthook config file."""

    path: str
    hooks: list[LefthookHookInfo] = field(default_factory=list)
    extends: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class LefthookStats:
    """Aggregate lefthook config analysis statistics."""

    config_files: int
    findings: int
    hooks: int = 0
    commands: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    name = path.name
    if name in CONFIG_NAMES:
        return True
    if path.parent.name == ".lefthook" and name.endswith((".yml", ".yaml")):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class LefthookAnalyzer:
    """Audit lefthook git hook configuration files for security risks.

    Scans lefthook.yml, lefthook.yaml, and .lefthook/*.yml for unpinned
    remote extends, hardcoded secrets in env blocks, curl-pipe-to-shell in
    run commands, sudo and chmod 777, git push --force, eval usage, TLS
    verification disabled, and sensitive path references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LefthookFinding] | None = None
        self._stats: LefthookStats | None = None
        self._infos: list[LefthookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return lefthook config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        lefthook_dir = self.root / ".lefthook"
        if lefthook_dir.is_dir():
            for path in sorted(lefthook_dir.rglob("*")):
                if path.is_file() and path.suffix in (".yml", ".yaml"):
                    found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yml")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yaml")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_run_value(
        self,
        run_value: str,
        lineno: int,
        rel: str,
        findings: list[LefthookFinding],
    ) -> None:
        if CURL_PIPE_SHELL_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in hook run command is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if RM_RF_ROOT_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="destructive_rm",
                    severity="high",
                    message="destructive rm -rf in hook run command",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if SUDO_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in hook run command — hooks should not require elevated privileges",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if CHMOD_777_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="chmod_777",
                    severity="high",
                    message="chmod 777 in hook run command",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if FORCE_PUSH_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="force_push",
                    severity="high",
                    message="git push --force in hook run command",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if EVAL_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in hook run command — avoid dynamic shell evaluation",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if DANGEROUS_SHELL_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell pattern in hook run command",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )
        if SENSITIVE_PATH_PATTERN.search(run_value):
            findings.append(
                LefthookFinding(
                    kind="sensitive_path",
                    severity="medium",
                    message="sensitive path referenced in hook run command",
                    path=rel,
                    lineno=lineno,
                    line=run_value,
                )
            )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LefthookFinding],
        info: LefthookInfo,
        current_hook: LefthookHookInfo | None,
        in_env_block: bool,
        in_extends: bool,
    ) -> tuple[LefthookHookInfo | None, bool, bool]:
        stripped = _strip_comment(line)
        if not stripped:
            return current_hook, in_env_block, in_extends

        if stripped == "extends:":
            return current_hook, in_env_block, True

        if in_extends and EXTEND_URL_PATTERN.match(stripped):
            url = stripped.split(":", 1)[1].strip()
            if url not in info.extends:
                info.extends.append(url)
            findings.append(
                LefthookFinding(
                    kind="remote_extend",
                    severity="medium",
                    message="remote lefthook extend — pin ref and verify the source",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_extends and EXTEND_PATH_PATTERN.match(stripped):
            path_value = stripped.split(":", 1)[1].strip()
            if path_value not in info.extends:
                info.extends.append(path_value)

        if in_extends and UNPINNED_REF_PATTERN.match(stripped):
            findings.append(
                LefthookFinding(
                    kind="unpinned_extend_ref",
                    severity="medium",
                    message="unpinned ref in lefthook extend — pin to a commit SHA or tag",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_extends and not stripped.startswith(("-", "url:", "path:", "ref:")):
            in_extends = False

        hook_match = HOOK_KEY_PATTERN.match(stripped)
        if hook_match:
            hook_name = hook_match.group(1)
            current_hook = LefthookHookInfo(name=hook_name)
            info.hooks.append(current_hook)
            in_env_block = False
            in_extends = False
            return current_hook, in_env_block, in_extends

        if current_hook and COMMAND_KEY_PATTERN.match(stripped) and stripped.endswith(":"):
            cmd_name = stripped.rstrip(":").strip()
            if cmd_name not in ("commands", "scripts", "jobs", "skip", "parallel", "piped"):
                if cmd_name not in current_hook.commands:
                    current_hook.commands.append(cmd_name)

        if current_hook and SCRIPT_KEY_PATTERN.match(stripped):
            script_name = stripped.rstrip(":").strip().strip("\"'")
            if script_name not in current_hook.scripts:
                current_hook.scripts.append(script_name)

        if current_hook and SKIP_ALL_PATTERN.match(stripped):
            current_hook.skip_all = True
            findings.append(
                LefthookFinding(
                    kind="skip_all_hooks",
                    severity="low",
                    message="hook block has skip: true — all checks in this hook are disabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_BLOCK_PATTERN.match(stripped):
            in_env_block = True
            return current_hook, in_env_block, in_extends

        run_match = RUN_LINE_PATTERN.match(stripped)
        if run_match:
            in_env_block = False
            self._scan_run_value(run_match.group(1), lineno, rel, findings)

        if (
            SECRET_VAR_PATTERN.search(stripped)
            or SECRET_ENV_VALUE_PATTERN.search(stripped)
            or (in_env_block and SECRET_VAR_PATTERN.search(line))
        ):
            findings.append(
                LefthookFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in lefthook config — use env vars or a secret manager",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in lefthook config — use credential helpers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in lefthook config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in SCM URL in lefthook config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled in lefthook config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if not stripped.startswith(" ") and not stripped.startswith("\t") and ":" in stripped:
            if not stripped.startswith(("-", "url:", "path:", "ref:")):
                in_env_block = False

        return current_hook, in_env_block, in_extends

    def _analyze_file(self, path: Path) -> tuple[list[LefthookFinding], LefthookInfo]:
        findings: list[LefthookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, LefthookInfo(path=rel)

        info = LefthookInfo(path=rel, lines=len(raw_lines))
        current_hook: LefthookHookInfo | None = None
        in_env_block = False
        in_extends = False

        for lineno, raw in enumerate(raw_lines, start=1):
            current_hook, in_env_block, in_extends = self._scan_line(
                raw, lineno, rel, findings, info, current_hook, in_env_block, in_extends
            )

        return findings, info

    def analyze(self) -> list[LefthookFinding]:
        """Scan lefthook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LefthookFinding] = []
        infos: list[LefthookInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        hooks = sum(len(i.hooks) for i in infos)
        commands = sum(len(h.commands) + len(h.scripts) for i in infos for h in i.hooks)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = LefthookStats(
            config_files=len(paths),
            findings=len(findings),
            hooks=hooks,
            commands=commands,
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
        """Return parsed lefthook config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
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
        """Scaffold a hardened lefthook configuration template."""
        return """\
# Generated by DevAI LefthookAnalyzer
min_version: 1.6.0

pre-commit:
  parallel: true
  commands:
    lint:
      run: ruff check src tests
      glob: "*.py"
    test:
      run: python -m pytest -q
      glob: "*.py"

pre-push:
  commands:
    audit:
      run: pip-audit

# Pin remote extends to a commit SHA or tag — never use main/master/HEAD
# extends:
#   - url: https://github.com/org/lefthook-config/raw/main/lefthook.yml
#     ref: v1.0.0

# Use env vars for secrets — never hardcode tokens in hook commands
# Avoid curl | sh, sudo, chmod 777, and git push --force in run commands
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Lefthook: no config files found"
        return (
            f"Lefthook: {stats.config_files} config(s), {stats.hooks} hook(s), "
            f"{stats.commands} command(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Lefthook configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  hooks: {stats.hooks}",
            f"  commands: {stats.commands}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.hooks)} hook(s)")
            if info.extends:
                lines.append(f"    extends: {', '.join(info.extends[:5])}")
            for hook in info.hooks:
                cmd_list = ", ".join(hook.commands[:5]) or "none"
                lines.append(f"      {hook.name}: [{cmd_list}]")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
