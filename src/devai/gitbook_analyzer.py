"""GitBookAnalyzer — audit .gitbook.yaml and book.json for documentation security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

GITBOOK_YAML_NAMES = (
    ".gitbook.yaml",
    ".gitbook.yml",
)
BOOK_JSON_NAME = "book.json"
GITBOOK_MARKERS = (
    "gitbook",
    "structure",
    "plugins",
    "pluginsconfig",
    "integrations",
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
    r"(?:url|repo_url|site_url|edit_uri)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
ROOT_OUTSIDE_PATTERN = re.compile(
    r"^\s*root\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)
INCLUDE_CODE_UNSAFE_PATTERN = re.compile(
    r"(?:include-code|include_code)\s*:[^\n]*(?:check\s*:\s*false|folder\s*:\s*['\"]?\.\./)",
    re.IGNORECASE,
)
INCLUDE_CODE_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*(?:include-code|include_code)\b",
    re.IGNORECASE,
)
VARIABLES_SECRET_PATTERN = re.compile(
    r"(?:variables|pluginsconfig)\s*:[^\n]*(?:secret|token|password|api[_-]?key)",
    re.IGNORECASE,
)
OLD_GITBOOK_VERSION_PATTERN = re.compile(
    r"(?:gitbook|version)\s*[=:]\s*['\"]?(?:2\.|1\.)|['\"]gitbook['\"]\s*:\s*['\"]?(?:2\.|1\.)",
    re.IGNORECASE,
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"^\s*-\s*https?://[^\s\"']+",
    re.IGNORECASE,
)
UNSAFE_REDIRECT_PATTERN = re.compile(
    r"(?:javascript:|data:)",
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
    has_integrations: bool = False


@dataclass
class GitBookStats:
    """Aggregate GitBook analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitbook_yaml(path: Path) -> bool:
    return path.name in GITBOOK_YAML_NAMES


def _looks_like_book_json(content: str) -> bool:
    lowered = content.lower()
    return any(marker in lowered for marker in GITBOOK_MARKERS) or '"gitbook"' in lowered


def _is_book_json(path: Path) -> bool:
    if path.name != BOOK_JSON_NAME:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_book_json(content)


class GitBookAnalyzer:
    """Audit GitBook configuration for documentation security and hygiene risks.

    Scans .gitbook.yaml and book.json for hardcoded secrets, unsafe root paths,
    include-code plugin misconfigurations, credentials in URLs, and legacy GitBook versions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitBookFinding] | None = None
        self._stats: GitBookStats | None = None
        self._infos: list[GitBookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return GitBook configuration paths found in the project."""
        found: list[Path] = []
        for name in GITBOOK_YAML_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        book_json = self.root / BOOK_JSON_NAME
        if book_json.is_file() and _is_book_json(book_json):
            found.append(book_json)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path not in found:
                if _is_gitbook_yaml(path) or _is_book_json(path):
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
            key = stripped[:-1].strip().lower()
            if key in ("plugins", "integrations", "variables", "config", "pluginsconfig"):
                section = key
            else:
                section = key

        if section == "plugins" and stripped.startswith("- "):
            plugin = stripped[2:].strip().strip("'\"")
            if plugin:
                info.plugins.append(plugin.split(":")[0])

        if section == "integrations":
            info.has_integrations = True

        if HARDCODED_SECRET_PATTERN.search(line):
            if section in ("variables", "pluginsconfig"):
                findings.append(
                    GitBookFinding(
                        kind="variables_secret",
                        severity="high",
                        message="sensitive value in variables/pluginsConfig — use GitBook secrets or env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            else:
                findings.append(
                    GitBookFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in GitBook config — use env vars or GitBook variables UI",
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
                    message="credentials embedded in URL — remove user:pass@ from integration URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ROOT_OUTSIDE_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="root_outside_project",
                    severity="high",
                    message="root points outside project directory — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INCLUDE_CODE_UNSAFE_PATTERN.search(line) or (
            INCLUDE_CODE_PLUGIN_PATTERN.search(stripped) and section == "plugins"
        ):
            findings.append(
                GitBookFinding(
                    kind="include_code_plugin",
                    severity="medium",
                    message="include-code plugin can read arbitrary files — restrict folder and enable check",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section in ("variables", "pluginsconfig") and VARIABLES_SECRET_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="variables_secret",
                    severity="high",
                    message="sensitive value in variables/pluginsConfig — use GitBook secrets or env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OLD_GITBOOK_VERSION_PATTERN.search(line):
            findings.append(
                GitBookFinding(
                    kind="old_gitbook_version",
                    severity="low",
                    message="legacy GitBook CLI version — migrate to GitBook.com or update to 3.x",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXTERNAL_SCRIPT_PATTERN.search(stripped):
            findings.append(
                GitBookFinding(
                    kind="external_script",
                    severity="medium",
                    message="remote script URL in GitBook config — self-host or pin with SRI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_REDIRECT_PATTERN.search(line) and (
            section in ("redirects", "redirect") or "redirect" in stripped.lower()
        ):
            findings.append(
                GitBookFinding(
                    kind="unsafe_redirect",
                    severity="high",
                    message="redirect uses javascript: or data: URI — use relative or HTTPS paths only",
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
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def _analyze_json_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel, format="json")

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="json")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info, "")

        try:
            data = json.loads("\n".join(raw_lines))
            if isinstance(data, dict):
                info.title = data.get("title")
                plugins = data.get("plugins", [])
                if isinstance(plugins, list):
                    info.plugins = [str(p) for p in plugins]
                if data.get("pluginsConfig") or data.get("integrations"):
                    info.has_integrations = True
        except (json.JSONDecodeError, OSError):
            pass

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        if path.name == BOOK_JSON_NAME:
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
root: ./docs/

structure:
  readme: README.md
  summary: SUMMARY.md

plugins:
  - search
  - github

integrations:
  github:
    url: https://github.com/org/repo

# Use GitBook UI or CI secrets for sensitive values — never commit secrets here
variables: {}

config:
  gitbook:
    version: 3.2.3
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
