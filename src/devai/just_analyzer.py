"""JustAnalyzer — audit justfile recipes for security risks."""

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
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
RECIPE_PATTERN = re.compile(r"^([a-zA-Z0-9_-]+)(?:\s+[^:]+)?:\s*$")
SET_PATTERN = re.compile(r"^set\s+(\w+)\s*:=?\s*(.+)$", re.IGNORECASE)


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
    """Parsed metadata from a justfile."""

    path: str
    lines: int = 0
    recipes: list[str] = field(default_factory=list)
    settings: list[str] = field(default_factory=list)


@dataclass
class JustStats:
    """Aggregate statistics from justfile analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_justfile(path: Path) -> bool:
    return path.name in JUSTFILE_NAMES or path.name.lower() == "justfile"


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


class JustAnalyzer:
    """Audit justfile recipes for security issues.

    Scans justfile/Justfile for hardcoded secrets, insecure HTTP URLs,
    credentials in git URLs, sensitive file references, curl piped to shell,
    and dangerous shell commands in recipe bodies.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JustFinding] | None = None
        self._stats: JustStats | None = None
        self._infos: list[JustInfo] | None = None

    def configs(self) -> list[Path]:
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
        in_recipe: bool,
    ) -> bool:
        if _is_comment_line(line):
            return in_recipe

        stripped = line.strip()

        recipe_match = RECIPE_PATTERN.match(stripped)
        if recipe_match and not stripped.startswith("set "):
            info.recipes.append(recipe_match.group(1))
            return True

        set_match = SET_PATTERN.match(stripped)
        if set_match:
            info.settings.append(set_match.group(1))
            if HARDCODED_SECRET_PATTERN.search(stripped):
                findings.append(
                    JustFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in justfile setting — use env vars or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            return False

        if in_recipe or (stripped and not stripped.endswith(":")):
            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    JustFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in justfile recipe — use env vars or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
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

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    JustFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for downloads and remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
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

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    JustFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive file path in recipe — avoid exposing secrets in task commands",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    JustFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_SHELL_PATTERN.search(line):
                findings.append(
                    JustFinding(
                        kind="dangerous_shell",
                        severity="high",
                        message="dangerous shell command in recipe — review for privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if stripped.endswith(":") and not stripped.startswith("set "):
            return True

        return in_recipe

    def _analyze_file(self, path: Path) -> tuple[list[JustFinding], JustInfo]:
        findings: list[JustFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, JustInfo(path=rel)

        raw_lines = text.splitlines()
        info = JustInfo(path=rel, lines=len(raw_lines))
        in_recipe = False

        for lineno, line in enumerate(raw_lines, start=1):
            in_recipe = self._scan_line(line, lineno, rel, findings, info, in_recipe)

        return findings, info

    def analyze(self) -> list[JustFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JustFinding] = []
        infos: list[JustInfo] = []
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
        self._stats = JustStats(
            configs=len(paths),
            files=len(paths),
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
        """Scaffold a hardened justfile snippet with secure defaults."""
        return """\
# justfile — hardened defaults for just projects

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Use env vars for secrets — never hardcode credentials
# export API_KEY := env_var("API_KEY")

default:
    @just --list

setup:
    # Avoid curl | sh — vendor scripts with checksum verification
    echo "Run project setup here"

test:
    pytest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Just configs: none found"
        return (
            f"Just configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Just analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            recipes = ", ".join(info.recipes[:8]) if info.recipes else "none"
            lines.append(
                f"  - {info.path}: {len(info.recipes)} recipe(s), recipes={recipes}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
