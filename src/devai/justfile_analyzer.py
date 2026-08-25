"""JustfileAnalyzer — audit justfile and Justfile for security and recipe safety."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JUSTFILE_NAMES = ("justfile", "Justfile", ".justfile")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
VAR_ASSIGNMENT_PATTERN = re.compile(
    r"^(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_-]*)\s*:=\s*(.+)$",
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*[=:]\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+(/|\$\(HOME\)|~|\*)|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*[=:]\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|--privileged\b|docker\.sock|/var/run/docker\.sock)",
    re.IGNORECASE,
)
DOTENV_LOAD_PATTERN = re.compile(
    r"(?:^\s*\[dotenv-load\]|^\s*set\s+dotenv-load\s*:=\s*true)",
    re.IGNORECASE,
)
RECIPE_HEADER_PATTERN = re.compile(
    r"^[a-zA-Z_@][a-zA-Z0-9_.-]*(?:\s+[a-zA-Z_][a-zA-Z0-9_-]*(?:\s*=\s*['\"][^'\"]*['\"])?)*\s*:$",
)
ATTRIBUTE_PATTERN = re.compile(r"^\[[^\]]+\]$")
IMPORT_PATTERN = re.compile(
    r"^import\??\s+['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
INTERPOLATION_PATTERN = re.compile(
    r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*\}\}",
)


@dataclass
class JustfileFinding:
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
class JustfileInfo:
    """Parsed metadata from a justfile."""

    path: str
    lines: int = 0
    recipes: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


@dataclass
class JustfileStats:
    """Aggregate justfile analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_justfile(path: Path) -> bool:
    return path.name in JUSTFILE_NAMES


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _strip_comment(line: str) -> str:
    if "#" in line:
        in_quote = False
        quote_char = ""
        for i, ch in enumerate(line):
            if ch in ("'", '"') and (i == 0 or line[i - 1] != "\\"):
                if not in_quote:
                    in_quote = True
                    quote_char = ch
                elif ch == quote_char:
                    in_quote = False
            elif ch == "#" and not in_quote:
                return line[:i]
    return line


class JustfileAnalyzer:
    """Audit just command runner files for security issues.

    Scans justfile, Justfile, and .justfile for hardcoded secrets in variable
    assignments, sensitive dotenv-load usage, dangerous recipe commands,
    curl piped to shell, privileged Docker, disabled TLS verification,
    insecure HTTP imports, and SCM credentials in URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JustfileFinding] | None = None
        self._stats: JustfileStats | None = None
        self._infos: list[JustfileInfo] | None = None

    def configs(self) -> list[Path]:
        """Return justfile paths found in the project."""
        found: list[Path] = []
        for name in JUSTFILE_NAMES:
            path = self.root / name
            if path.is_file() and _is_justfile(path):
                found.append(path)
        for path in sorted(self.root.rglob("justfile")):
            if path.is_file() and path not in found and _is_justfile(path):
                found.append(path)
        for path in sorted(self.root.rglob("Justfile")):
            if path.is_file() and path not in found and _is_justfile(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[JustfileFinding],
        info: JustfileInfo,
        *,
        in_recipe: bool,
        in_export: bool,
        has_dotenv_load: bool,
    ) -> None:
        content = _strip_comment(line).strip()
        if not content or _is_comment_line(content):
            return

        if VAR_ASSIGNMENT_PATTERN.match(content):
            match = VAR_ASSIGNMENT_PATTERN.match(content)
            if match:
                var_name = match.group(1)
                info.variables.append(var_name)
                if content.lstrip().startswith("export "):
                    info.exports.append(var_name)
                    in_export = True

            if HARDCODED_SECRET_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in justfile variable — use environment variables or a secret manager",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )
            elif in_export and re.search(
                r"(?:password|secret|token|api[_-]?key|credential)",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    JustfileFinding(
                        kind="exported_secret",
                        severity="high",
                        message="exported variable may leak secrets to recipe environment",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

        if has_dotenv_load and SENSITIVE_PATH_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="sensitive_dotenv",
                    severity="medium",
                    message="dotenv-load may expose sensitive files — use .env.example and keep secrets out of repo",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        if in_recipe or VAR_ASSIGNMENT_PATTERN.match(content) is None:
            if CURL_PIPE_SHELL_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in recipe — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

            if DANGEROUS_SHELL_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="dangerous_shell",
                        severity="high",
                        message="dangerous shell command in recipe — review for privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker or docker.sock mount in recipe",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

            if TLS_VERIFY_OFF_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="tls_verify_disabled",
                        severity="high",
                        message="TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(content):
                findings.append(
                    JustfileFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive file path referenced in justfile",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(content) and not VAR_ASSIGNMENT_PATTERN.match(content):
            findings.append(
                JustfileFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in justfile — use environment variables or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="possible AWS access key in justfile",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in SCM URL — use SSH keys or credential helpers",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        if INSECURE_HTTP_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in justfile — prefer HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        if ENV_SECRET_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="env_secret",
                    severity="high",
                    message="environment-style secret assignment in justfile",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

        import_match = IMPORT_PATTERN.match(content)
        if import_match:
            import_path = import_match.group(1)
            info.imports.append(import_path)
            if import_path.startswith("http://"):
                findings.append(
                    JustfileFinding(
                        kind="insecure_import",
                        severity="medium",
                        message="justfile import over insecure HTTP — use HTTPS or local paths",
                        path=rel,
                        lineno=lineno,
                        line=line.rstrip(),
                    )
                )

        if DOTENV_LOAD_PATTERN.search(content):
            findings.append(
                JustfileFinding(
                    kind="dotenv_load",
                    severity="medium",
                    message="dotenv-load enabled — ensure .env is gitignored and secrets are not committed",
                    path=rel,
                    lineno=lineno,
                    line=line.rstrip(),
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[JustfileFinding], JustfileInfo]:
        findings: list[JustfileFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JustfileInfo(path=rel)

        info = JustfileInfo(path=rel, lines=len(raw_lines))
        in_recipe = False
        recipe_indent = -1
        pending_dotenv = False

        for lineno, raw_line in enumerate(raw_lines, start=1):
            line = raw_line.rstrip("\n")
            content = _strip_comment(line).strip()

            if not content:
                in_recipe = False
                pending_dotenv = False
                continue

            if ATTRIBUTE_PATTERN.match(content):
                if "dotenv-load" in content.lower():
                    pending_dotenv = True
                continue

            if RECIPE_HEADER_PATTERN.match(content):
                recipe_name = content.split(":")[0].strip().split()[0]
                info.recipes.append(recipe_name)
                in_recipe = True
                recipe_indent = len(line) - len(line.lstrip())
                has_dotenv = pending_dotenv
                pending_dotenv = False
                if has_dotenv:
                    self._scan_line(
                        line,
                        lineno,
                        rel,
                        findings,
                        info,
                        in_recipe=False,
                        in_export=False,
                        has_dotenv_load=True,
                    )
                continue

            if content.startswith("set "):
                in_recipe = False
                pending_dotenv = False
            elif not line.startswith((" ", "\t")) and not content.startswith("import"):
                in_recipe = False
                pending_dotenv = False

            indent = len(line) - len(line.lstrip())
            if in_recipe and indent <= recipe_indent and content:
                in_recipe = False

            is_export = content.lstrip().startswith("export ")
            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_recipe=in_recipe,
                in_export=is_export,
                has_dotenv_load=pending_dotenv or bool(DOTENV_LOAD_PATTERN.search(content)),
            )

        return findings, info

    def analyze(self) -> list[JustfileFinding]:
        """Scan justfiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JustfileFinding] = []
        infos: list[JustfileInfo] = []
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
        self._stats = JustfileStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JustfileStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JustfileInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        return """\
# Generated by DevAI JustfileAnalyzer
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Load env from a gitignored file — never commit secrets
set dotenv-load := false

default:
    @just --list

install:
    pip install -e ".[dev]"

test:
    python -m pytest

lint:
    ruff check src tests
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Justfiles: none found"
        return (
            f"Justfiles: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Justfile analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            recipes = ", ".join(info.recipes[:8]) if info.recipes else "none"
            lines.append(f"  - {info.path}: {len(info.recipes)} recipe(s), recipes={recipes}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
