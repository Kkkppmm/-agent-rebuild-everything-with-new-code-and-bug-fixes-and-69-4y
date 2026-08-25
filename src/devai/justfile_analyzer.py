"""JustfileAnalyzer — audit Justfile for security and command-runner safety."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JUSTFILE_NAMES = ("Justfile", "justfile")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]+\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*[:=]+\s*"
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
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|--privileged\b|docker\.sock|/var/run/docker\.sock)",
    re.IGNORECASE,
)
JUST_INJECTION_PATTERN = re.compile(
    r"\{\{\s*(?:justfile_directory|justfile|invocation_directory|invocation_file)\s*\}\}",
    re.IGNORECASE,
)
VAR_ASSIGN_PATTERN = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*:=\s*(.+)$",
)
RECIPE_PATTERN = re.compile(
    r"^([a-zA-Z0-9@_-]+(?:\s+[a-zA-Z_][a-zA-Z0-9_]*(?:='[^']*'|=\"[^\"]*\")?)*)\s*:(?!=)"
)
DOTENV_LOAD_PATTERN = re.compile(r"\[dotenv(?:-load)?\]", re.IGNORECASE)


@dataclass
class JustfileFinding:
    """A security or best-practice issue in a Justfile."""

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
    """Parsed metadata from a Justfile."""

    path: str
    lines: int = 0
    recipes: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
    dotenv_load: bool = False


@dataclass
class JustfileStats:
    """Aggregate Justfile analysis statistics."""

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
                return line[:i].rstrip()
    return line.rstrip()


class JustfileAnalyzer:
    """Audit just command runner Justfiles for security issues.

    Scans Justfile and justfile for hardcoded secrets in variable assignments,
    sensitive dotenv loading, curl piped to shell, privileged Docker,
    disabled TLS verification, SCM credentials in URLs, and dangerous shell
    commands in recipe bodies.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JustfileFinding] | None = None
        self._stats: JustfileStats | None = None
        self._infos: list[JustfileInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Justfile paths found in the project."""
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
        findings: list[JustfileFinding],
        info: JustfileInfo,
        in_recipe: bool,
    ) -> None:
        if _is_comment_line(line):
            return

        stripped = _strip_comment(line).strip()
        if not stripped:
            return

        if DOTENV_LOAD_PATTERN.search(stripped):
            info.dotenv_load = True
            findings.append(
                JustfileFinding(
                    kind="dotenv_load",
                    severity="medium",
                    message="dotenv-load loads .env into recipes — ensure .env is gitignored and not committed",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        var_match = VAR_ASSIGN_PATTERN.match(stripped)
        if var_match:
            name = var_match.group(1)
            value = var_match.group(2).strip()
            info.variables.append(name)
            if HARDCODED_SECRET_PATTERN.search(stripped) or ENV_SECRET_PATTERN.search(stripped):
                findings.append(
                    JustfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in variable — use environment or secret store",
                        path=rel,
                        lineno=lineno,
                        line=line.strip(),
                    )
                )
            elif value and not value.startswith("env_var(") and re.match(r'^["\'][^"\']+["\']$', value):
                if re.search(
                    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)",
                    name,
                    re.IGNORECASE,
                ):
                    findings.append(
                        JustfileFinding(
                            kind="sensitive_env_var",
                            severity="medium",
                            message=f"sensitive variable {name} has a literal value — prefer secret injection",
                            path=rel,
                            lineno=lineno,
                            line=line.strip(),
                        )
                    )

        if SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive path referenced in Justfile",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in recipe is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(stripped):
            kind = "destructive_command"
            if "sudo" in stripped.lower():
                kind = "sudo_usage"
            findings.append(
                JustfileFinding(
                    kind=kind,
                    severity="high" if kind != "sudo_usage" else "medium",
                    message="dangerous shell command in recipe — review for privilege escalation or data loss",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and remote resources",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in SCM URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="possible AWS access key in Justfile",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if PRIVILEGED_DOCKER_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="privileged_docker",
                    severity="high",
                    message="privileged Docker or docker.sock mount — avoid container privilege escalation",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if in_recipe and JUST_INJECTION_PATTERN.search(stripped):
            findings.append(
                JustfileFinding(
                    kind="just_injection",
                    severity="low",
                    message="just built-in variable in command — ensure inputs are sanitized",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[JustfileFinding], JustfileInfo]:
        findings: list[JustfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JustfileInfo(path=rel)

        info = JustfileInfo(path=rel, lines=len(raw_lines))
        in_recipe = False
        recipe_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = _strip_comment(line)
            content = stripped.strip()
            indent = len(line) - len(line.lstrip())

            recipe_match = RECIPE_PATTERN.match(content)
            if recipe_match and not content.startswith("["):
                recipe_name = recipe_match.group(1).split()[0]
                info.recipes.append(recipe_name)
                in_recipe = False
                recipe_indent = indent
                continue

            if in_recipe and indent <= recipe_indent and content and not content.startswith("["):
                in_recipe = False

            if recipe_indent >= 0 and indent > recipe_indent and content:
                in_recipe = True

            self._scan_line(line, lineno, rel, findings, info, in_recipe=in_recipe)

        return findings, info

    def analyze(self) -> list[JustfileFinding]:
        """Scan Justfiles and return findings."""
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

default:
    @just --list

install:
    pip install -e ".[dev]"

test:
    python -m pytest
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
