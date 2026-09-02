"""MkDocsAnalyzer — audit MkDocs documentation configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("mkdocs.yml", "mkdocs.yaml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*"
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
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:[\"'](?:\.\./|\.\.\\|/etc/|/tmp/|\.ssh/|~/)[\"']|"
    r"(?:docs_dir|site_dir|watch)\s*:\s*(?:\.\./|\.\.\\|/etc/|/tmp/))",
    re.IGNORECASE,
)
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:docs_dir|site_dir|theme_dir|extra_css|extra_javascript|watch)\s*:\s*[\"']/[^\"']*[\"']",
    re.IGNORECASE,
)
DEV_ADDR_EXPOSED_PATTERN = re.compile(
    r"dev_addr\s*:\s*[\"']?(?:0\.0\.0\.0|\*|\[::\])[\"']?",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(r"strict\s*:\s*false\b", re.IGNORECASE)
USE_DIRECTORY_URLS_FALSE_PATTERN = re.compile(
    r"use_directory_urls\s*:\s*false\b",
    re.IGNORECASE,
)
NAV_KEY_PATTERN = re.compile(r"^\s*nav\s*:", re.IGNORECASE)
SITE_URL_PATTERN = re.compile(r"^\s*site_url\s*:", re.IGNORECASE)
REPO_URL_PATTERN = re.compile(r"^\s*repo_url\s*:", re.IGNORECASE)
EDIT_URI_PATTERN = re.compile(r"^\s*edit_uri\s*:", re.IGNORECASE)
DOCS_DIR_PATTERN = re.compile(
    r"^\s*docs_dir\s*:\s*[\"']?([^\"'\n#]+)[\"']?",
    re.IGNORECASE,
)
PLUGINS_LINE_PATTERN = re.compile(r"^\s*plugins\s*:", re.IGNORECASE)
SEARCH_PLUGIN_PATTERN = re.compile(r"(?:^|\s)(?:-|\s)search\b", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CDN_SCRIPT_NO_INTEGRITY_PATTERN = re.compile(
    r"extra_javascript\s*:\s*[\"']https?://[^\"']+[\"']",
    re.IGNORECASE,
)


@dataclass
class MkDocsFinding:
    """A security or best-practice issue in an MkDocs configuration."""

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
    site_name: str = ""
    site_url: str = ""
    repo_url: str = ""
    docs_dir: str = ""
    has_nav: bool = False
    has_search_plugin: bool = False


@dataclass
class MkDocsStats:
    """Aggregate MkDocs analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class MkDocsAnalyzer:
    """Audit MkDocs configs for secrets, insecure URLs, path traversal, and doc site risks.

    Scans mkdocs.yml/mkdocs.yaml for hardcoded secrets, insecure HTTP site/repo URLs,
    SCM credentials, path traversal in docs_dir and watch paths, exposed dev_addr,
    disabled strict mode, missing nav/site_url, and CDN scripts without integrity.
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
        return found

    def _record_metadata(self, line: str, info: MkDocsInfo) -> None:
        for key, pattern in (
            ("site_name", r"^\s*site_name\s*:\s*[\"']?([^\"'\n#]+)[\"']?"),
            ("site_url", r"^\s*site_url\s*:\s*[\"']?([^\"'\n#]+)[\"']?"),
            ("repo_url", r"^\s*repo_url\s*:\s*[\"']?([^\"'\n#]+)[\"']?"),
        ):
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == "site_name":
                    info.site_name = value
                elif key == "site_url":
                    info.site_url = value
                elif key == "repo_url":
                    info.repo_url = value

        docs_match = DOCS_DIR_PATTERN.match(line)
        if docs_match:
            info.docs_dir = docs_match.group(1).strip()

        if NAV_KEY_PATTERN.match(line):
            info.has_nav = True
        if SEARCH_PLUGIN_PATTERN.search(line):
            info.has_search_plugin = True

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MkDocsFinding],
        info: MkDocsInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        self._record_metadata(line, info)

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="possible hardcoded secret or credential in MkDocs config",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="SCM credentials embedded in URL",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for site_url, repo_url, or asset links",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if PATH_TRAVERSAL_PATTERN.search(line) or ABSOLUTE_PATH_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="path_traversal",
                    severity="high",
                    message="suspicious absolute or traversal path in docs_dir, watch, or asset config",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if DEV_ADDR_EXPOSED_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="dev_addr_exposed",
                    severity="medium",
                    message="dev_addr binds to all interfaces — restrict to localhost in config",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="strict_disabled",
                    severity="medium",
                    message="strict: false allows broken internal links to ship",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if USE_DIRECTORY_URLS_FALSE_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="directory_urls_disabled",
                    severity="low",
                    message="use_directory_urls: false hurts SEO and canonical URL structure",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in MkDocs config or plugin hook",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if CDN_SCRIPT_NO_INTEGRITY_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="cdn_script_no_integrity",
                    severity="low",
                    message="external extra_javascript from CDN without subresource integrity",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[MkDocsFinding], MkDocsInfo]:
        findings: list[MkDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MkDocsInfo(path=rel)

        info = MkDocsInfo(path=rel, lines=len(raw_lines))
        has_plugins_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if PLUGINS_LINE_PATTERN.match(line.strip()):
                has_plugins_section = True
            self._scan_line(line, lineno, rel, findings, info)

        if not info.has_nav:
            findings.append(
                MkDocsFinding(
                    kind="missing_nav",
                    severity="low",
                    message="no nav section — documentation structure may be hard to navigate",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if not info.site_url:
            findings.append(
                MkDocsFinding(
                    kind="missing_site_url",
                    severity="medium",
                    message="site_url not set — canonical URLs and sitemap may be incorrect",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if not info.repo_url:
            findings.append(
                MkDocsFinding(
                    kind="missing_repo_url",
                    severity="low",
                    message="repo_url not set — edit-on-GitHub links will not work",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if has_plugins_section and not info.has_search_plugin:
            findings.append(
                MkDocsFinding(
                    kind="search_plugin_missing",
                    severity="low",
                    message="plugins section present but search plugin not listed",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[MkDocsFinding]:
        """Scan MkDocs config files and return findings."""
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
        """Scaffold a hardened mkdocs.yml template."""
        return """\
# Generated by DevAI MkDocsAnalyzer
site_name: My Project Docs
site_url: https://docs.example.com/
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/
docs_dir: docs
strict: true
use_directory_urls: true

theme:
  name: material
  features:
    - navigation.sections
    - content.code.copy

plugins:
  - search
  - minify:
      minify_html: true

nav:
  - Home: index.md
  - Guide: guide.md

extra:
  social:
    - icon: fontawesome/brands/github
      link: https://github.com/org/repo

# Use HTTPS URLs only; keep docs_dir repo-relative
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
        for info in self.infos:
            site = info.site_name or "unspecified"
            docs = info.docs_dir or "docs"
            lines.append(
                f"  - {info.path}: site={site}, docs_dir={docs}, nav={'yes' if info.has_nav else 'no'}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
