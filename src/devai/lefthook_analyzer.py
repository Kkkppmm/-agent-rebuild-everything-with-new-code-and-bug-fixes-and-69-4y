"""LefthookAnalyzer — audit Lefthook git hook configs for security risks."""

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
    ".lefthook-local.yml",
    ".lefthook-local.yaml",
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
SKIP_ALL_PATTERN = re.compile(r"^\s*skip\s*:\s*(true|yes|1)\s*$", re.IGNORECASE)
RUN_COMMAND_PATTERN = re.compile(r"^\s*run\s*:", re.IGNORECASE)
HOOK_ENTRY_PATTERN = re.compile(
    r"^(pre-commit|pre-push|commit-msg|prepare-commit-msg|"
    r"post-commit|post-checkout|post-merge|post-rewrite|"
    r"reference-transaction|pre-rebase|pre-auto-gc)\s*:\s*$",
    re.IGNORECASE,
)
COMMAND_ENTRY_PATTERN = re.compile(r"^\s{4}([a-zA-Z0-9#@:_-]+)\s*:\s*$")
SCRIPT_ENTRY_PATTERN = re.compile(r"^\s{4}['\"]?[^'\"]+\.(sh|bash|zsh|ps1)['\"]?\s*:\s*$", re.IGNORECASE)
EXTENDS_BLOCK_PATTERN = re.compile(r"^\s*extends\s*:", re.IGNORECASE)
REMOTE_BLOCK_PATTERN = re.compile(r"^\s*remote\s*:", re.IGNORECASE)
ENV_BLOCK_PATTERN = re.compile(r"^\s*env\s*:", re.IGNORECASE)


@dataclass
class LefthookFinding:
    """A security or best-practice issue in a Lefthook config."""

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
    """Parsed metadata about a Lefthook config file."""

    path: str
    hooks: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    extends: list[str] = field(default_factory=list)
    has_remote: bool = False
    env_keys: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class LefthookStats:
    """Aggregate Lefthook analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_lefthook_config(path: Path) -> bool:
    return path.name in LEFTHOOK_NAMES


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class LefthookAnalyzer:
    """Audit Lefthook git hook configs for security risks and best practices.

    Scans lefthook.yml, lefthook.yaml, and lefthook-local.yml for curl-pipe-to-shell,
    destructive rm -rf, sudo usage, secrets in env blocks, chmod 777, git force-push,
    eval usage, remote extends, skip-all bypass, and dangerous shell commands in hooks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LefthookFinding] | None = None
        self._stats: LefthookStats | None = None
        self._infos: list[LefthookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Lefthook config paths found in the project."""
        found: list[Path] = []
        for name in LEFTHOOK_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yml")):
            if path.is_file() and path not in found and _is_lefthook_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("lefthook*.yaml")):
            if path.is_file() and path not in found and _is_lefthook_config(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LefthookFinding],
        info: LefthookInfo,
        in_hook: bool,
    ) -> bool:
        stripped = _strip_comment(line)
        if not stripped:
            return in_hook

        if REMOTE_BLOCK_PATTERN.match(stripped):
            info.has_remote = True
            findings.append(
                LefthookFinding(
                    kind="remote_config",
                    severity="low",
                    message="remote Lefthook config — ensure ref is pinned and source is trusted",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        hook_match = HOOK_ENTRY_PATTERN.match(line.rstrip())
        if hook_match:
            hook_name = hook_match.group(1).strip()
            if hook_name not in info.hooks:
                info.hooks.append(hook_name)
            return True

        if not line.startswith(" ") and not line.startswith("\t") and stripped.endswith(":"):
            return False

        if in_hook and COMMAND_ENTRY_PATTERN.match(line.rstrip()):
            cmd_name = COMMAND_ENTRY_PATTERN.match(line.rstrip()).group(1).strip()  # type: ignore[union-attr]
            if cmd_name not in info.commands:
                info.commands.append(cmd_name)

        if in_hook and SCRIPT_ENTRY_PATTERN.match(line.rstrip()):
            script_name = line.strip().rstrip(":").strip().strip("'\"")
            if script_name not in info.scripts:
                info.scripts.append(script_name)

        if EXTENDS_BLOCK_PATTERN.match(stripped):
            extend_ref = stripped.split(":", 1)[-1].strip().strip("-\"' ")
            if extend_ref and extend_ref not in info.extends:
                info.extends.append(extend_ref)

        if REMOTE_EXTEND_PATTERN.match(stripped):
            extend_url = stripped.lstrip("-").strip().strip("'\"")
            if extend_url and extend_url not in info.extends:
                info.extends.append(extend_url)
            findings.append(
                LefthookFinding(
                    kind="remote_extend",
                    severity="medium",
                    message="remote Lefthook extend — pin sources and verify checksums",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_ALL_PATTERN.match(stripped):
            findings.append(
                LefthookFinding(
                    kind="skip_all_hooks",
                    severity="medium",
                    message="skip: true disables all hooks — use targeted skip rules instead",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_BLOCK_PATTERN.match(stripped):
            key = stripped.split(":", 1)[0].strip()
            if key and key not in info.env_keys:
                info.env_keys.append(key)

        if SECRET_VAR_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Lefthook config — use env vars or a secret manager",
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
                    message="AWS access key in Lefthook config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell is unsafe in git hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RM_RF_ROOT_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="destructive_rm",
                    severity="high",
                    message="destructive rm -rf on root or home directory",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in hook command — avoid privilege escalation in git hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHMOD_777_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="chmod_777",
                    severity="high",
                    message="chmod 777 grants world-writable permissions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_PUSH_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="force_push",
                    severity="medium",
                    message="git push --force can overwrite remote history",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="eval_usage",
                    severity="medium",
                    message="eval in hook command can execute arbitrary code",
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
                    message="insecure HTTP URL — use HTTPS for remote extends and downloads",
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
                    message="credentials embedded in URL — use SSH keys or token env vars",
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
                    message="TLS verification disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in hook — review script logic",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                LefthookFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive path reference — avoid exposing credential files in hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RUN_COMMAND_PATTERN.match(stripped) and "curl" in stripped.lower() and "|" in stripped:
            if not any(f.kind == "curl_pipe_shell" and f.lineno == lineno for f in findings):
                findings.append(
                    LefthookFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell is unsafe in git hooks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return in_hook

    def _analyze_file(self, path: Path) -> tuple[list[LefthookFinding], LefthookInfo]:
        findings: list[LefthookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, LefthookInfo(path=rel)

        info = LefthookInfo(path=rel, lines=len(raw_lines))
        in_hook = False

        for lineno, raw in enumerate(raw_lines, start=1):
            in_hook = self._scan_line(raw, lineno, rel, findings, info, in_hook)

        return findings, info

    def analyze(self) -> list[LefthookFinding]:
        """Scan Lefthook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LefthookFinding] = []
        infos: list[LefthookInfo] = []
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
        self._stats = LefthookStats(
            config_files=len(paths),
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
        """Return parsed Lefthook metadata."""
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
        """Scaffold a hardened Lefthook config template."""
        return """\
# Generated by DevAI LefthookAnalyzer
min_version: 1.6.0

pre-commit:
  parallel: true
  commands:
    lint:
      run: ruff check src tests
    test:
      run: python -m pytest -q

pre-push:
  commands:
    typecheck:
      run: mypy src

# Use env vars for secrets — never hardcode tokens in hook commands
# Avoid curl | sh — vendor scripts with checksum verification
# Avoid sudo, chmod 777, and git push --force in hook commands
# Pin remote extends to trusted sources — prefer local extends
# Use targeted skip rules instead of skip: true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Lefthook configs: none found"
        return (
            f"Lefthook configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Lefthook analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            hooks = ", ".join(info.hooks[:8]) if info.hooks else "none"
            lines.append(
                f"  - {info.path}: {len(info.hooks)} hook(s), "
                f"{len(info.commands)} command(s)"
            )
            lines.append(f"    hooks: {hooks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
