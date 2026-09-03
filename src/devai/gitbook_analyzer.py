"""GitBookAnalyzer — audit .gitbook.yaml and book.json for documentation security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".gitbook.yaml",
    ".gitbook.yml",
    "book.json",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:['\"]?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)['\"]?\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:repo_url|site_url|edit_uri|url)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
ROOT_PARENT_PATTERN = re.compile(
    r"^\s*root\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)
REDIRECT_EXTERNAL_PATTERN = re.compile(
    r"^\s*['\"]?[^'\"]+['\"]?\s*:\s*https?://",
    re.IGNORECASE,
)
GIT_SYNC_CREDENTIAL_PATTERN = re.compile(
    r"(?:git|github|gitlab|bitbucket)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
PLUGIN_GA_TOKEN_PATTERN = re.compile(
    r"(?:ga|google-analytics|gtag)\s*:\s*[^\n]*['\"]?[A-Z]{2}-[A-Z0-9-]+['\"]?",
    re.IGNORECASE,
)
VARIABLE_SECRET_PATTERN = re.compile(
    r"^\s*['\"]?(?:api[_-]?key|secret|token|password)['\"]?\s*:",
    re.IGNORECASE,
)
PDF_EXPORT_PATTERN = re.compile(
    r"^\s*pdf\s*:\s*$|^\s*-\s*pdf\b",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:plugin|plugins)\s*:\s*[^\n]*https?://|^\s*-\s*https?://",
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
    format: str = "yaml"
    title: str | None = None
    plugins: list[str] = field(default_factory=list)
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


def _is_gitbook_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class GitBookAnalyzer:
    """Audit GitBook configuration for documentation security and hygiene risks.

    Scans .gitbook.yaml/.gitbook.yml and book.json for hardcoded secrets,
    open redirects, unsafe root paths, embedded git credentials, and exposed tokens.
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
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_gitbook_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GitBookFinding],
        info: GitBookInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip().strip("'\"")
            if key in ("plugins", "redirects", "variables", "structure", "pdf"):
                section = key
            else:
                section = key

        if stripped.startswith("title:"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "plugins" and stripped.startswith("- "):
            plugin = stripped[2:].strip().strip("'\"")
            if plugin:
                info.plugins.append(plugin.split(":")[0])

        if section == "redirects":
            info.has_redirects = True
        if section == "variables":
            info.has_variables = True

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in GitBook config — use env vars or GitBook variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in GitBook config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in GitBook config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CREDENTIAL_IN_URL_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="credential_in_url",
                    severity="high",
                    message="credentials embedded in URL — remove user:pass@ from repo/site URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ROOT_PARENT_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="root_parent_path",
                    severity="medium",
                    message="root points outside project directory — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "redirects" and REDIRECT_EXTERNAL_PATTERN.search(stripped):
            findings.append(
                GitBookFinding(
                    kind="open_redirect",
                    severity="medium",
                    message="redirect targets external URL — review for open-redirect abuse",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_SYNC_CREDENTIAL_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="git_sync_credentials",
                    severity="high",
                    message="git sync URL contains embedded credentials — use SSH keys or tokens",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PLUGIN_GA_TOKEN_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="analytics_token_inline",
                    severity="low",
                    message="analytics token inline in config — prefer GitBook environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "variables" and VARIABLE_SECRET_PATTERN.search(stripped):
            findings.append(
                GitBookFinding(
                    kind="variable_secret",
                    severity="high",
                    message="sensitive variable defined in config — use GitBook secrets or CI env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PDF_EXPORT_PATTERN.search(stripped):
            findings.append(
                GitBookFinding(
                    kind="pdf_export",
                    severity="low",
                    message="PDF export enabled — ensure internal docs are not publicly downloadable",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_PLUGIN_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="remote_plugin",
                    severity="high",
                    message="remote plugin URL in config — only install plugins from trusted sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_json_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return findings, GitBookInfo(path=rel, format="json")

        info = GitBookInfo(path=rel, lines=content.count("\n") + 1, format="json")
        if isinstance(data, dict):
            info.title = data.get("title")
            plugins = data.get("plugins", [])
            if isinstance(plugins, list):
                info.plugins = [str(p) for p in plugins]
            info.has_redirects = "redirect" in data or "redirects" in data

        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.rstrip()
            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    GitBookFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in book.json — use env vars or GitBook variables",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    GitBookFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in book.json — rotate and use env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    GitBookFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in book.json — use HTTPS endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if CREDENTIAL_IN_URL_PATTERN.search(line):
                findings.append(
                    GitBookFinding(
                        kind="credential_in_url",
                        severity="high",
                        message="credentials embedded in URL in book.json — remove user:pass@",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        if path.name == "book.json":
            return self._analyze_json_file(path)

        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel)

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="yaml")
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

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

# Use GitBook environment variables for secrets — never commit tokens here
variables: {}

# Prefer relative redirects within the documentation site
redirects: {}

# Review plugins before enabling — avoid loading from remote URLs
plugins: []
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
