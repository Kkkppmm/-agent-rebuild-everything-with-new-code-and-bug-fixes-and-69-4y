"""MkDocsAnalyzer — audit mkdocs.yml for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "mkdocs.yml",
    "mkdocs.yaml",
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
    r"(?:repo_url|site_url|edit_uri)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(
    r"^\s*strict\s*:\s*false\b",
    re.IGNORECASE,
)
DEV_ADDR_EXPOSED_PATTERN = re.compile(
    r"^\s*dev_addr\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
MACROS_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*(?:mkdocs-)?macros\b|^\s*macros\s*:\s*$",
    re.IGNORECASE,
)
SNIPPETS_BASE_PATH_PATTERN = re.compile(
    r"(?:base_path|check_paths)\s*:\s*[^\n]*(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"^\s*-\s*https?://[^\s\"']+",
    re.IGNORECASE,
)
EXTERNAL_STYLE_PATTERN = re.compile(
    r"^\s*-\s*https?://[^\s\"']+",
    re.IGNORECASE,
)
WATCH_PARENT_PATTERN = re.compile(
    r"^\s*-\s*['\"]?\.\./",
    re.IGNORECASE,
)
REMOTE_INCLUDE_PATTERN = re.compile(
    r"(?:pymdownx\.snippets|markdown_include)\b[^\n]*(?:https?://|file://)",
    re.IGNORECASE,
)
GOOGLE_ANALYTICS_INLINE_PATTERN = re.compile(
    r"(?:google_analytics|gtag)\s*:\s*['\"]?[A-Z]{2}-[A-Z0-9-]+['\"]?",
    re.IGNORECASE,
)
INSECURE_COOKIE_PATTERN = re.compile(
    r"(?:cookie_consent|extra)\s*:[^\n]*secure\s*:\s*false",
    re.IGNORECASE,
)
DISABLED_NAV_PATTERN = re.compile(
    r"^\s*validation\s*:\s*[^\n]*nav\s*:\s*ignore\b",
    re.IGNORECASE,
)


@dataclass
class MkDocsFinding:
    """A security or best-practice issue in an MkDocs configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MkDocsInfo:
    """Parsed metadata about an MkDocs configuration file."""

    path: str
    lines: int = 0
    site_name: str | None = None
    plugins: list[str] = field(default_factory=list)
    has_extra_javascript: bool = False
    has_extra_css: bool = False


@dataclass
class MkDocsStats:
    """Aggregate MkDocs analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_mkdocs_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class MkDocsAnalyzer:
    """Audit MkDocs configuration for documentation security and hygiene risks.

    Scans mkdocs.yml/mkdocs.yaml for hardcoded secrets, exposed dev servers,
    unsafe plugins, remote script includes, relaxed validation, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MkDocsFinding] | None = None
        self._stats: MkDocsStats | None = None
        self._infos: list[MkDocsInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return MkDocs configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_mkdocs_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MkDocsFinding],
        info: MkDocsInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in ("plugins", "markdown_extensions", "extra_javascript", "extra_css", "watch"):
                section = key
            elif key == "extra":
                section = "extra"
            else:
                section = key

        if stripped.startswith("site_name:"):
            info.site_name = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "plugins" and stripped.startswith("- "):
            plugin = stripped[2:].strip().strip("'\"")
            if plugin:
                info.plugins.append(plugin.split(":")[0])

        if section == "extra_javascript":
            info.has_extra_javascript = True
        if section == "extra_css":
            info.has_extra_css = True

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in MkDocs config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in MkDocs config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in MkDocs config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CREDENTIAL_IN_URL_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="credential_in_url",
                    severity="high",
                    message="credentials embedded in repo_url/site_url/edit_uri — remove user:pass@",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="strict_false",
                    severity="medium",
                    message="strict: false disables broken-link validation — keep strict enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEV_ADDR_EXPOSED_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="dev_addr_exposed",
                    severity="medium",
                    message="dev_addr binds to all interfaces — use 127.0.0.1 for local dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MACROS_PLUGIN_PATTERN.search(stripped):
            findings.append(
                MkDocsFinding(
                    kind="macros_plugin",
                    severity="medium",
                    message="mkdocs-macros executes Jinja templates — restrict include_dir and review macros",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SNIPPETS_BASE_PATH_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="snippets_unsafe_path",
                    severity="high",
                    message="pymdownx.snippets base_path outside project — restrict to trusted directories",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "extra_javascript" and EXTERNAL_SCRIPT_PATTERN.search(stripped):
            findings.append(
                MkDocsFinding(
                    kind="external_script",
                    severity="medium",
                    message="extra_javascript loads remote script — pin version and use SRI or self-host",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "extra_css" and EXTERNAL_STYLE_PATTERN.search(stripped):
            findings.append(
                MkDocsFinding(
                    kind="external_stylesheet",
                    severity="low",
                    message="extra_css loads remote stylesheet — pin version or self-host assets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WATCH_PARENT_PATTERN.search(stripped):
            findings.append(
                MkDocsFinding(
                    kind="watch_parent_path",
                    severity="medium",
                    message="watch includes parent directory — restrict to project paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_INCLUDE_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="remote_include",
                    severity="high",
                    message="markdown extension includes remote content — only include trusted local files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_NAV_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="nav_validation_disabled",
                    severity="low",
                    message="nav validation ignored — broken navigation links may go unnoticed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[MkDocsFinding], MkDocsInfo]:
        findings: list[MkDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MkDocsInfo(path=rel)

        info = MkDocsInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def analyze(self) -> list[MkDocsFinding]:
        """Scan MkDocs configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MkDocsFinding] = []
        infos: list[MkDocsInfo] = []
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
        self._stats = MkDocsStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MkDocsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MkDocsInfo]:
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
        """Scaffold a hardened MkDocs configuration template."""
        return """\
# Generated by DevAI MkDocsAnalyzer
site_name: My Project Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/

strict: true
dev_addr: 127.0.0.1:8000

theme:
  name: material
  features:
    - content.code.copy

plugins:
  - search
  - git-revision-date-localized

markdown_extensions:
  - admonition
  - pymdownx.highlight
  - pymdownx.superfences

nav:
  - Home: index.md

# Self-host assets instead of loading remote scripts/stylesheets
extra_javascript: []
extra_css: []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "MkDocs configs: none found"
        return (
            f"MkDocs configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "MkDocs analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
