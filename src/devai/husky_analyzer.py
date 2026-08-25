"""HuskyAnalyzer — audit Husky git hook scripts and package.json configs for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

HUSKY_DIR = ".husky"
HUSKY_RC_NAMES = (
    ".huskyrc",
    ".huskyrc.json",
    ".huskyrc.js",
    ".huskyrc.cjs",
    ".huskyrc.mjs",
)
PACKAGE_JSON_NAMES = ("package.json",)

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
HUSKY_BYPASS_PATTERN = re.compile(r"\bHUSKY\s*=\s*0\b", re.IGNORECASE)
NPX_LATEST_PATTERN = re.compile(r"\bnpx\s+[^\s@]+@(?:latest|next|canary)\b", re.IGNORECASE)
UNPINNED_NPX_PATTERN = re.compile(r"\bnpx\s+--yes\s+[^\s@]+\b(?![@/])", re.IGNORECASE)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n]*\s+-o\s+[^\n]*\s*&&\s*(?:sh|bash|chmod)",
    re.IGNORECASE,
)
SHEBANG_PATTERN = re.compile(r"^#!")


@dataclass
class HuskyFinding:
    """A security or best-practice issue in a Husky hook or config."""

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
class HuskyHookInfo:
    """Parsed metadata about a Husky hook script."""

    name: str
    path: str
    lines: int = 0
    has_shebang: bool = False


@dataclass
class HuskyInfo:
    """Parsed metadata about Husky configuration in a project."""

    hooks: list[HuskyHookInfo] = field(default_factory=list)
    package_json_husky: bool = False
    legacy_hooks: list[str] = field(default_factory=list)
    huskyrc_files: list[str] = field(default_factory=list)


@dataclass
class HuskyStats:
    """Aggregate Husky analysis statistics."""

    hook_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    legacy_hooks: int = 0
    huskyrc_files: int = 0


def _is_hook_file(path: Path) -> bool:
    name = path.name
    if name.startswith("_"):
        return False
    if name in ("commit-msg", "pre-commit", "pre-push", "post-commit", "post-checkout",
                "post-merge", "post-rewrite", "pre-rebase", "prepare-commit-msg",
                "pre-auto-gc", "pre-applypatch", "post-applypatch", "applypatch-msg"):
        return True
    return path.suffix in ("", ".sh") and not name.endswith(".sample")


class HuskyAnalyzer:
    """Audit Husky git hook scripts and configs for security risks and best practices.

    Scans ``.husky/`` hook scripts, legacy ``package.json`` husky hooks, and
    ``.huskyrc`` files for curl-pipe-to-shell, hardcoded secrets, sudo usage,
    destructive commands, and other dangerous patterns in git hooks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HuskyFinding] | None = None
        self._stats: HuskyStats | None = None
        self._info: HuskyInfo | None = None

    def hook_files(self) -> list[Path]:
        """Return Husky hook script paths found in the project."""
        found: list[Path] = []
        husky_dir = self.root / HUSKY_DIR
        if husky_dir.is_dir():
            for path in sorted(husky_dir.iterdir()):
                if path.is_file() and _is_hook_file(path):
                    found.append(path)
        return found

    def huskyrc_files(self) -> list[Path]:
        """Return Husky RC config paths found in the project."""
        found: list[Path] = []
        for name in HUSKY_RC_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HuskyFinding],
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "piping curl/wget to shell is unsafe in git hooks"),
            (RM_RF_ROOT_PATTERN, "destructive_rm", "high",
             "destructive rm -rf in git hooks can wipe the filesystem"),
            (SUDO_PATTERN, "sudo_usage", "high",
             "sudo in git hooks can escalate privileges unexpectedly"),
            (CHMOD_777_PATTERN, "chmod_777", "high",
             "chmod 777 in git hooks weakens file permissions"),
            (FORCE_PUSH_PATTERN, "force_push", "high",
             "git push --force in hooks can overwrite remote history"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval in git hooks can execute arbitrary code"),
            (AWS_ACCESS_KEY_PATTERN, "hardcoded_secret", "high",
             "possible AWS access key in hook script"),
            (SCM_CREDENTIALS_PATTERN, "hardcoded_secret", "high",
             "credentials embedded in SCM URL"),
            (SECRET_VAR_PATTERN, "hardcoded_secret", "high",
             "possible hardcoded secret in hook script"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in hook script"),
            (TLS_VERIFY_OFF_PATTERN, "tls_verify_disabled", "high",
             "TLS verification disabled in hook script"),
            (DANGEROUS_SHELL_PATTERN, "dangerous_shell", "high",
             "dangerous shell pattern in hook script"),
            (SENSITIVE_PATH_PATTERN, "sensitive_path", "medium",
             "hook references sensitive file or credential path"),
            (HUSKY_BYPASS_PATTERN, "husky_bypass", "medium",
             "HUSKY=0 disables all hooks — use targeted skip instead"),
            (NPX_LATEST_PATTERN, "unpinned_npx", "medium",
             "npx with floating tag (@latest/@next) is not reproducible"),
            (UNPINNED_NPX_PATTERN, "unpinned_npx", "medium",
             "npx --yes without version pin can pull arbitrary code"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "high",
             "downloading and executing remote script in hook"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    HuskyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

    def _analyze_hook(self, path: Path) -> tuple[list[HuskyFinding], HuskyHookInfo]:
        findings: list[HuskyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HuskyHookInfo(name=path.name, path=rel)

        has_shebang = bool(raw_lines and SHEBANG_PATTERN.match(raw_lines[0]))
        info = HuskyHookInfo(
            name=path.name,
            path=rel,
            lines=len(raw_lines),
            has_shebang=has_shebang,
        )

        if raw_lines and not has_shebang and path.name not in ("_",):
            findings.append(
                HuskyFinding(
                    kind="missing_shebang",
                    severity="low",
                    message="hook script missing shebang — add #!/usr/bin/env sh",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw, lineno, rel, findings)

        return findings, info

    def _analyze_huskyrc(self, path: Path) -> list[HuskyFinding]:
        findings: list[HuskyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw, lineno, rel, findings)

        return findings

    def _analyze_package_json(self) -> tuple[list[HuskyFinding], list[str]]:
        findings: list[HuskyFinding] = []
        legacy_hooks: list[str] = []
        pkg_path = self.root / "package.json"
        if not pkg_path.is_file():
            return findings, legacy_hooks

        rel = str(pkg_path.relative_to(self.root))
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return findings, legacy_hooks

        husky_config = data.get("husky")
        if isinstance(husky_config, dict):
            hooks = husky_config.get("hooks", {})
            if isinstance(hooks, dict):
                for hook_name, command in hooks.items():
                    legacy_hooks.append(hook_name)
                    if not isinstance(command, str):
                        continue
                    findings.append(
                        HuskyFinding(
                            kind="legacy_inline_hook",
                            severity="medium",
                            message=(
                                f"legacy inline husky hook '{hook_name}' in package.json "
                                "— migrate to .husky/ scripts for auditability"
                            ),
                            path=rel,
                            lineno=0,
                            line=command[:120],
                        )
                    )
                    self._scan_line(command, 0, rel, findings)

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            prepare = scripts.get("prepare", "")
            if isinstance(prepare, str) and "husky" in prepare.lower():
                if "husky install" not in prepare and "husky" in prepare:
                    findings.append(
                        HuskyFinding(
                            kind="nonstandard_prepare",
                            severity="low",
                            message="non-standard husky prepare script — prefer 'husky' or 'husky install'",
                            path=rel,
                            lineno=0,
                            line=prepare,
                        )
                    )

        return findings, legacy_hooks

    def analyze(self) -> list[HuskyFinding]:
        """Scan Husky hooks and configs, returning findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HuskyFinding] = []
        hooks: list[HuskyHookInfo] = []
        huskyrc_paths: list[str] = []

        for path in self.hook_files():
            hook_findings, info = self._analyze_hook(path)
            findings.extend(hook_findings)
            hooks.append(info)

        for path in self.huskyrc_files():
            huskyrc_paths.append(str(path.relative_to(self.root)))
            findings.extend(self._analyze_huskyrc(path))

        pkg_findings, legacy_hooks = self._analyze_package_json()
        findings.extend(pkg_findings)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._info = HuskyInfo(
            hooks=hooks,
            package_json_husky=bool(legacy_hooks),
            legacy_hooks=legacy_hooks,
            huskyrc_files=huskyrc_paths,
        )
        self._stats = HuskyStats(
            hook_files=len(hooks),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
            legacy_hooks=len(legacy_hooks),
            huskyrc_files=len(huskyrc_paths),
        )
        return findings

    @property
    def stats(self) -> HuskyStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def info(self) -> HuskyInfo:
        """Return parsed Husky metadata."""
        if self._info is None:
            self.analyze()
        return self._info  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no hooks)."""
        self.analyze()
        stats = self.stats
        if stats.hook_files == 0 and stats.legacy_hooks == 0 and stats.huskyrc_files == 0:
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
        """Scaffold hardened Husky hook templates."""
        return """\
# Generated by DevAI HuskyAnalyzer
# Save as .husky/pre-commit

#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npm test
# Or: npx lint-staged

# Save as .husky/pre-push

#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npm run typecheck

# Security best practices:
# - Use env vars for secrets — never hardcode tokens in hook scripts
# - Avoid curl | sh — vendor scripts with checksum verification
# - Avoid sudo, chmod 777, and git push --force in hooks
# - Pin npx package versions (e.g. npx eslint@8.57.0)
# - Migrate legacy package.json husky.hooks to .husky/ scripts
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.hook_files == 0 and stats.legacy_hooks == 0 and stats.huskyrc_files == 0:
            return "Husky configs: none found"
        parts = [f"{stats.hook_files} hook file(s)"]
        if stats.legacy_hooks:
            parts.append(f"{stats.legacy_hooks} legacy hook(s)")
        if stats.huskyrc_files:
            parts.append(f"{stats.huskyrc_files} huskyrc file(s)")
        return (
            f"Husky: {', '.join(parts)}, "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        info = self.info
        lines = [
            "Husky analysis:",
            f"  hook files: {stats.hook_files}",
            f"  legacy hooks: {stats.legacy_hooks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for hook in info.hooks:
            shebang = "yes" if hook.has_shebang else "no"
            lines.append(f"  - {hook.path}: {hook.lines} line(s), shebang: {shebang}")
        if info.legacy_hooks:
            lines.append(f"  legacy hooks in package.json: {', '.join(info.legacy_hooks)}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
