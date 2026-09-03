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
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
JSON_SECRET_PATTERN = re.compile(
    r"[\"'](?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"https?://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
PARENT_PATH_PATTERN = re.compile(
    r"(?:readme|summary|root)\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)
GIT_PLUGIN_PATTERN = re.compile(
    r"(?:git\+|github:|gitlab:|bitbucket:)[^\s\"']+",
    re.IGNORECASE,
)
UNPINNED_NPM_PLUGIN_PATTERN = re.compile(
    r"(?:plugins|pluginsConfig)\s*:[^\n]*@[^\d/]",
    re.IGNORECASE,
)
SERVE_ALL_INTERFACES_PATTERN = re.compile(
    r"(?:host|listen|dev_addr)\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
VARIABLES_SECTION_PATTERN = re.compile(r"^\s*variables\s*:\s*$", re.IGNORECASE)
PLUGINS_SECTION_PATTERN = re.compile(r"^\s*plugins\s*:\s*$", re.IGNORECASE)


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
    has_plugins: bool = False
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
    insecure URLs, parent-path traversal, unpinned plugins, and exposed dev servers.
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

    def _scan_yaml_line(
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

        if VARIABLES_SECTION_PATTERN.match(stripped):
            section = "variables"
            info.has_variables = True
            return section
        if PLUGINS_SECTION_PATTERN.match(stripped):
            section = "plugins"
            info.has_plugins = True
            return section
        if stripped and not stripped.startswith("-") and ":" in stripped and not stripped.startswith(" "):
            section = stripped.split(":", 1)[0].strip().lower()

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="Hardcoded secret or credential in GitBook config — use environment variables",
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
                    message="URL embeds credentials — remove secrets from repo URLs",
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
                    message="Insecure HTTP URL — prefer HTTPS for documentation links",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PARENT_PATH_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="parent_path",
                    severity="medium",
                    message="Structure path references parent directory — restrict to project root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_PLUGIN_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="git_plugin",
                    severity="medium",
                    message="Plugin loaded from git URL — pin commit SHA and review source",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_NPM_PLUGIN_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="unpinned_plugin",
                    severity="low",
                    message="NPM plugin without version pin — pin plugin versions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SERVE_ALL_INTERFACES_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="serve_all_interfaces",
                    severity="medium",
                    message="Dev server binds to all interfaces — use 127.0.0.1 for local preview",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "variables" and re.search(
            r"^\s+\w+\s*:\s*[\"'][^\"'\s${}][^\"']*[\"']",
            line,
        ):
            findings.append(
                GitBookFinding(
                    kind="variable_literal",
                    severity="medium",
                    message="Literal value in variables section — use GitBook env vars for secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_yaml_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel, format="yaml")

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="yaml")
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_yaml_line(line, lineno, rel, findings, info, section)

        return findings, info

    def _analyze_json_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
            data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return findings, GitBookInfo(path=rel, format="json")

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="json")
        if isinstance(data, dict):
            if data.get("plugins"):
                info.has_plugins = True
            if data.get("variables") or data.get("pluginsConfig"):
                info.has_variables = True

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if (
                HARDCODED_SECRET_PATTERN.search(line)
                or JSON_SECRET_PATTERN.search(line)
                or AWS_ACCESS_KEY_PATTERN.search(line)
            ):
                findings.append(
                    GitBookFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret or credential in book.json — use environment variables",
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
                        message="URL embeds credentials — remove secrets from repo URLs",
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
                        message="Insecure HTTP URL — prefer HTTPS for documentation links",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if GIT_PLUGIN_PATTERN.search(line):
                findings.append(
                    GitBookFinding(
                        kind="git_plugin",
                        severity="medium",
                        message="Plugin loaded from git URL — pin commit SHA and review source",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        if path.suffix == ".json":
            return self._analyze_json_file(path)
        return self._analyze_yaml_file(path)

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

# Use GitBook environment variables for secrets — never commit literals here
variables: {}

plugins: []

redirects: {}
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
