"""JustAnalyzer — audit justfile and Just recipes for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JUSTFILE_NAMES = ("justfile", "Justfile", ".justfile")
JUST_SUFFIX = ".just"

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(?:password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
EXPORT_SECRET_PATTERN = re.compile(
    r"^export\s+[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*:=",
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
SCRIPT_SHEBANG_PATTERN = re.compile(r"^\s*\[(?:script|python|bash|sh|zsh)\]", re.IGNORECASE)
IMPORT_HTTP_PATTERN = re.compile(r"^\s*import\s+['\"]https?://", re.IGNORECASE)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example|\.local)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
RECIPE_PATTERN = re.compile(r"^([a-zA-Z0-9_-]+(?:\s+[a-zA-Z0-9_-]+)*)\s*:")


@dataclass
class JustFinding:
    """A security or best-practice issue in a justfile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JustInfo:
    """Parsed metadata about a justfile."""

    path: str
    recipes: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    mods: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class JustStats:
    """Aggregate justfile analysis statistics."""

    justfiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_justfile(path: Path) -> bool:
    name = path.name
    if name in JUSTFILE_NAMES or name.lower() == "justfile":
        return True
    if name.endswith(JUST_SUFFIX):
        return True
    if path.parent.name == "just" and name.endswith(JUST_SUFFIX):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class JustAnalyzer:
    """Audit justfiles for security risks and task-runner best practices.

    Scans justfile, Justfile, .justfile, and just/*.just for curl-pipe-to-shell,
    destructive rm -rf, sudo usage, secrets in variables, chmod 777, git force-push,
    eval usage, insecure HTTP imports, script shebang recipes, and sensitive paths.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JustFinding] | None = None
        self._stats: JustStats | None = None
        self._infos: list[JustInfo] | None = None

    def justfiles(self) -> list[Path]:
        """Return justfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_justfile(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[JustFinding],
        info: JustInfo,
    ) -> None:
        stripped = _strip_comment(line)
        if not stripped:
            return

        recipe_match = RECIPE_PATTERN.match(stripped)
        if recipe_match:
            recipe_name = recipe_match.group(1).strip()
            if recipe_name not in info.recipes:
                info.recipes.append(recipe_name)

        if stripped.lower().startswith("export ") and ":=" in stripped:
            export_name = stripped.split("export", 1)[1].split(":=")[0].strip()
            if export_name and export_name not in info.exports:
                info.exports.append(export_name)

        if stripped.lower().startswith("import "):
            import_path = stripped.split("import", 1)[1].strip().strip("\"'")
            if import_path not in info.imports:
                info.imports.append(import_path)

        if stripped.lower().startswith("mod "):
            mod_name = stripped.split("mod", 1)[1].strip()
            if mod_name and mod_name not in info.mods:
                info.mods.append(mod_name)

        if (
            SECRET_VAR_PATTERN.search(stripped)
            or EXPORT_SECRET_PATTERN.search(stripped)
        ):
            findings.append(
                JustFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in justfile — use env vars or a secret manager",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(stripped):
            findings.append(
                JustFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in justfile — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(stripped):
            findings.append(
                JustFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RM_RF_ROOT_PATTERN.search(stripped):
            findings.append(
                JustFinding(
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
                JustFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in recipe — avoid privilege escalation in task scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHMOD_777_PATTERN.search(stripped):
            findings.append(
                JustFinding(
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
                JustFinding(
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
                JustFinding(
                    kind="eval_usage",
                    severity="medium",
                    message="eval in just recipe can execute arbitrary code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                JustFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and imports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(stripped):
            findings.append(
                JustFinding(
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
                JustFinding(
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
                JustFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in just recipe — review script logic",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCRIPT_SHEBANG_PATTERN.match(stripped):
            findings.append(
                JustFinding(
                    kind="script_shebang",
                    severity="low",
                    message="script shebang recipe — review embedded script for injection risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IMPORT_HTTP_PATTERN.match(stripped):
            findings.append(
                JustFinding(
                    kind="insecure_import",
                    severity="medium",
                    message="import from HTTP URL — use local just modules or HTTPS with pinning",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                JustFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive path reference — avoid exposing credential files in recipes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[JustFinding], JustInfo]:
        findings: list[JustFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JustInfo(path=rel)

        info = JustInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[JustFinding]:
        """Scan justfiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JustFinding] = []
        infos: list[JustInfo] = []
        paths = self.justfiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = JustStats(
            justfiles=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JustStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JustInfo]:
        """Return parsed justfile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no justfiles)."""
        self.analyze()
        stats = self.stats
        if stats.justfiles == 0:
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
        """Scaffold a hardened justfile template."""
        return """\
# Generated by DevAI JustAnalyzer

# Use env vars for secrets — never hardcode tokens in recipes
# export api_token := env_var('API_TOKEN')

default:
    just --list

install:
    pip install -e ".[dev]"

test:
    python -m pytest

lint:
    ruff check src tests

# Avoid curl | sh — vendor scripts with checksum verification
# Avoid sudo, chmod 777, and git push --force in recipes
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.justfiles == 0:
            return "Justfiles: none found"
        return (
            f"Justfiles: {stats.justfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Justfile analysis:",
            f"  justfiles: {stats.justfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            recipes = ", ".join(info.recipes[:8]) if info.recipes else "none"
            lines.append(
                f"  - {info.path}: {len(info.recipes)} recipe(s), "
                f"{len(info.exports)} export(s)"
            )
            lines.append(f"    recipes: {recipes}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
