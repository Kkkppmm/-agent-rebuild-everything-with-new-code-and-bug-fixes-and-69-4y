"""HuskyAnalyzer — audit Husky git hook scripts for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

HUSKY_DIR = ".husky"
HOOK_NAMES = (
    "pre-commit",
    "pre-push",
    "commit-msg",
    "post-commit",
    "post-checkout",
    "post-merge",
    "prepare-commit-msg",
)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]\s*"
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
UNPINNED_NPX_PATTERN = re.compile(
    r"\bnpx\s+(?!--yes\s+--package\s+)[a-zA-Z@][^\s|;&]*\b",
    re.IGNORECASE,
)
HOOK_DISABLED_PATTERN = re.compile(r"^\s*#\s*husky\s+disabled", re.IGNORECASE)
EXIT_ZERO_PATTERN = re.compile(r"^\s*exit\s+0\s*$", re.IGNORECASE)


@dataclass
class HuskyFinding:
    """A security or best-practice issue in a Husky hook script."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HuskyHookInfo:
    """Parsed metadata about a Husky hook script."""

    name: str
    path: str
    lines: int = 0
    disabled: bool = False
    commands: list[str] = field(default_factory=list)


@dataclass
class HuskyInfo:
    """Parsed metadata about Husky installation in a project."""

    path: str
    hooks: list[HuskyHookInfo] = field(default_factory=list)
    prepare_script: str | None = None
    husky_version: str | None = None


@dataclass
class HuskyStats:
    """Aggregate Husky analysis statistics."""

    hook_files: int = 0
    findings: int = 0
    hooks: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_hook_file(path: Path) -> bool:
    if path.parent.name != HUSKY_DIR:
        return False
    if path.name.startswith("_"):
        return False
    return path.is_file() and not path.suffix


class HuskyAnalyzer:
    """Audit Husky git hook scripts for security risks.

    Scans .husky/* hook scripts and package.json husky/prepare config for
    hardcoded secrets, curl-pipe-to-shell, sudo and chmod 777, git push
  --force, eval usage, TLS verification disabled, unpinned npx commands,
    disabled hooks, and sensitive path references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HuskyFinding] | None = None
        self._stats: HuskyStats | None = None
        self._info: HuskyInfo | None = None

    def hook_files(self) -> list[Path]:
        """Return Husky hook script paths found in the project."""
        husky_dir = self.root / HUSKY_DIR
        if not husky_dir.is_dir():
            return []
        found: list[Path] = []
        for path in sorted(husky_dir.iterdir()):
            if _is_hook_file(path):
                found.append(path)
        return found

    def _read_package_husky(self) -> HuskyInfo:
        info = HuskyInfo(path=HUSKY_DIR)
        pkg = self.root / "package.json"
        if not pkg.is_file():
            return info
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return info
        if not isinstance(data, dict):
            return info
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            prepare = scripts.get("prepare")
            if isinstance(prepare, str) and "husky" in prepare:
                info.prepare_script = prepare
        dev_deps = data.get("devDependencies", {})
        deps = data.get("dependencies", {})
        for source in (dev_deps, deps):
            if isinstance(source, dict) and "husky" in source:
                info.husky_version = str(source["husky"])
        return info

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HuskyFinding],
        hook_info: HuskyHookInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if HOOK_DISABLED_PATTERN.match(stripped):
                hook_info.disabled = True
                findings.append(
                    HuskyFinding(
                        kind="hook_disabled",
                        severity="medium",
                        message="husky hook explicitly disabled — verify this is intentional",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            return

        if stripped and not stripped.startswith("#"):
            hook_info.commands.append(stripped[:120])

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in hook — supply-chain risk on every commit/push",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RM_RF_ROOT_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="rm_rf_root",
                    severity="high",
                    message="rm -rf / or home in hook — catastrophic data loss risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="sudo",
                    severity="high",
                    message="sudo in git hook — hooks should not require elevated privileges",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHMOD_777_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="chmod_777",
                    severity="high",
                    message="chmod 777 in hook — overly permissive file permissions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_PUSH_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="force_push",
                    severity="high",
                    message="git push --force in hook — can bypass branch protection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="eval",
                    severity="high",
                    message="eval in hook script — arbitrary code execution risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SECRET_VAR_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in hook — use env vars or a secret manager",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in hook — use credential helpers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in hook script",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in SCM URL in hook",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="tls_verify_off",
                    severity="high",
                    message="TLS verification disabled in hook — MITM risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in hook script",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="sensitive_path",
                    severity="medium",
                    message="sensitive file path referenced in hook",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_NPX_PATTERN.search(line):
            findings.append(
                HuskyFinding(
                    kind="unpinned_npx",
                    severity="medium",
                    message="unpinned npx command — pin package version to avoid supply-chain drift",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXIT_ZERO_PATTERN.match(stripped):
            findings.append(
                HuskyFinding(
                    kind="noop_hook",
                    severity="low",
                    message="hook exits 0 immediately — verify checks are not bypassed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_hook(self, path: Path) -> tuple[list[HuskyFinding], HuskyHookInfo]:
        findings: list[HuskyFinding] = []
        rel = str(path.relative_to(self.root))
        hook_info = HuskyHookInfo(name=path.name, path=rel)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, hook_info

        hook_info.lines = len(raw_lines)
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, hook_info)

        if hook_info.lines <= 3 and not hook_info.commands:
            findings.append(
                HuskyFinding(
                    kind="empty_hook",
                    severity="low",
                    message="hook script appears empty — add lint/test checks or remove unused hook",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, hook_info

    def analyze(self) -> list[HuskyFinding]:
        """Scan Husky hooks and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HuskyFinding] = []
        info = self._read_package_husky()
        paths = self.hook_files()

        if info.prepare_script and "husky install" in info.prepare_script:
            findings.append(
                HuskyFinding(
                    kind="legacy_husky_install",
                    severity="low",
                    message="husky install in prepare script — migrate to Husky v9+ init format",
                    path="package.json",
                    lineno=1,
                    line=info.prepare_script,
                )
            )

        for path in paths:
            file_findings, hook_info = self._analyze_hook(path)
            findings.extend(file_findings)
            info.hooks.append(hook_info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._info = info
        self._stats = HuskyStats(
            hook_files=len(paths),
            findings=len(findings),
            hooks=len(paths),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HuskyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def info(self) -> HuskyInfo:
        if self._info is None:
            self.analyze()
        return self._info  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.hook_files == 0 and not self.info.prepare_script:
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
# .husky/pre-commit
npm test
npx --yes --package lint-staged@15.4.3 lint-staged

# .husky/pre-push
npm run build
npm test

# package.json scripts (Husky v9+)
# "scripts": { "prepare": "husky" }
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.hook_files == 0 and not self.info.prepare_script:
            return "Husky: no hooks found"
        return (
            f"Husky: {stats.hook_files} hook(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        info = self.info
        lines = [
            "Husky hook analysis:",
            f"  hook files: {stats.hook_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        if info.prepare_script:
            lines.append(f"  prepare script: {info.prepare_script}")
        if info.husky_version:
            lines.append(f"  husky version: {info.husky_version}")
        for hook in info.hooks:
            status = "disabled" if hook.disabled else "active"
            lines.append(f"  - {hook.name} ({status}): {hook.lines} line(s)")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
