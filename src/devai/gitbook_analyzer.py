"""GitBookAnalyzer — audit .gitbook.yaml and book.json for security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAMES = (
    ".gitbook.yaml",
    ".gitbook.yml",
    "book.json",
)

GITBOOK_MARKERS = (
    "gitbook",
    "structure",
    "plugins",
    "pluginsconfig",
    "plugins_config",
    "summary",
    "variables",
    "redirects",
)

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
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:url|site|base|repository|edit[-_]?url)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
GIT_TOKEN_PATTERN = re.compile(
    r"(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:additional[-_]?js|script|src)\s*[=:]\s*['\"]?https?://",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:plugin|require|import)\s*[=:]\s*['\"]?https?://",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"(?:redirect|destination)\s*[=:]\s*['\"]https?://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
FUNCTION_CONSTRUCTOR_PATTERN = re.compile(r"\bFunction\s*\(")
INLINE_HTML_PLUGIN_PATTERN = re.compile(
    r"(?:html|allow[-_]?html|dangerous[-_]?html)\s*[=:]\s*true",
    re.IGNORECASE,
)
EXPOSED_VARIABLE_SECRET_PATTERN = re.compile(
    r"(?:variables|pluginsConfig|plugins_config)\s*[=:][^\n]*"
    r"(?:secret|token|apiKey|password|privateKey)",
    re.IGNORECASE,
)
GITHUB_TOKEN_IN_CONFIG_PATTERN = re.compile(
    r"(?:token|access[-_]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{10,}['\"]?",
    re.IGNORECASE,
)
JSON_SECRET_KEY_PATTERN = re.compile(
    r'"(?:apiKey|accessToken|secretKey|authToken|privateKey|password|secret)"\s*:\s*"[^"${}][^"]*"',
    re.IGNORECASE,
)


@dataclass
class GitBookFinding:
    """A security or best-practice issue in a GitBook configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class GitBookInfo:
    """Parsed metadata about a GitBook configuration file."""

    path: str
    lines: int = 0
    root: str | None = None
    has_plugins: bool = False
    has_redirects: bool = False
    has_variables: bool = False


@dataclass
class GitBookStats:
    """Aggregate GitBook analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_gitbook_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in GITBOOK_MARKERS)


def _is_gitbook_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES and not path.name.startswith(".gitbook."):
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_gitbook_config(content)


class GitBookAnalyzer:
    """Audit GitBook configuration for documentation security and hygiene risks.

    Scans .gitbook.yaml and book.json for hardcoded secrets, git tokens in
    pluginsConfig, remote script loading, open redirects, and unsafe HTML settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitBookFinding] | None = None
        self._stats: GitBookStats | None = None
        self._infos: list[GitBookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return GitBook configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_gitbook_config(path):
                found.append(path)
        for path in sorted(self.root.rglob(".gitbook.*")):
            if path.is_file() and _is_gitbook_config(path) and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("book.json")):
            if path.is_file() and _is_gitbook_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GitBookFinding],
        info: GitBookInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            return

        if stripped.startswith("root:") or stripped.startswith('"root"'):
            value = stripped.split(":", 1)[1].strip().strip("'\",")
            if value:
                info.root = value

        if "plugins:" in stripped.lower() or '"plugins"' in stripped.lower():
            info.has_plugins = True

        if "redirects:" in stripped.lower() or '"redirects"' in stripped.lower():
            info.has_redirects = True

        if "variables:" in stripped.lower() or '"variables"' in stripped.lower():
            info.has_variables = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in GitBook config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in GitBook config — rotate and use env vars"),
            (GIT_TOKEN_PATTERN, "git_token", "high", "git token in GitBook config — revoke and use CI secrets"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in GitBook config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium", "remote script in GitBook config — self-host or pin trusted sources"),
            (REMOTE_PLUGIN_PATTERN, "remote_plugin", "high", "remote plugin URL in GitBook config — only load trusted local packages"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "medium", "external redirect in GitBook config — review redirect destinations"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in GitBook config — avoid dynamic code execution in config"),
            (FUNCTION_CONSTRUCTOR_PATTERN, "eval_exec", "high", "Function constructor in GitBook config — avoid dynamic code execution in config"),
            (INLINE_HTML_PLUGIN_PATTERN, "inline_html", "high", "HTML rendering enabled in GitBook config — XSS risk in rendered content"),
            (EXPOSED_VARIABLE_SECRET_PATTERN, "exposed_variable", "high", "secret exposed via GitBook variables — use server-side env vars"),
            (GITHUB_TOKEN_IN_CONFIG_PATTERN, "github_token", "high", "GitHub token in pluginsConfig — use env vars or CI secrets"),
            (JSON_SECRET_KEY_PATTERN, "hardcoded_secret", "high", "hardcoded secret in GitBook JSON config — use env vars or CI secrets"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    GitBookFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel)

        info = GitBookInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[GitBookFinding]:
        """Scan GitBook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitBookFinding] = []
        infos: list[GitBookInfo] = []
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
        self._stats = GitBookStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitBookStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitBookInfo]:
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
        """Scaffold a hardened GitBook configuration template."""
        return """\
# Generated by DevAI GitBookAnalyzer
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

variables:
  version: "1.0.0"

plugins:
  - theme-default
  - search
  - highlight

pluginsConfig:
  github:
    url: https://github.com/org/repo
    # token: use GITBOOK_GITHUB_TOKEN env var instead of hardcoding

pdf:
  fontSize: 12
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "GitBook configs: none found"
        return (
            f"GitBook configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "GitBook analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
