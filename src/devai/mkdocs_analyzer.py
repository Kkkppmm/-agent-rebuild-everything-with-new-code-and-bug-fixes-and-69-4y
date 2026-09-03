"""MkDocsAnalyzer — audit MkDocs documentation configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("mkdocs.yml", "mkdocs.yaml")

HTTP_SITE_URL_PATTERN = re.compile(r"^\s*site_url:\s*http://", re.IGNORECASE)
DEV_ADDR_PUBLIC_PATTERN = re.compile(
    r"^\s*dev_addr:\s*['\"]?(0\.0\.0\.0|::)[\"']?",
    re.IGNORECASE,
)
SECRET_IN_CONFIG_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*-\s*mkdocs-[a-zA-Z0-9_-]+(?![=<>!~])",
    re.IGNORECASE,
)
REMOTE_CONTENT_PATTERN = re.compile(
    r"(use_directory_urls|remote_content|fetch_remote)",
    re.IGNORECASE,
)
EXEC_IN_PLUGIN_PATTERN = re.compile(
    r"(os\.system|subprocess|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)


@dataclass
class MkDocsFinding:
    """A security or best-practice issue in an MkDocs config file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MkDocsPluginInfo:
    """Parsed metadata about an MkDocs plugin entry."""

    name: str
    options: list[str] = field(default_factory=list)


@dataclass
class MkDocsInfo:
    """Parsed metadata about an MkDocs config file."""

    path: str
    site_name: str | None = None
    site_url: str | None = None
    plugins: list[MkDocsPluginInfo] = field(default_factory=list)
    has_nav: bool = False
    lines: int = 0


@dataclass
class MkDocsStats:
    """Aggregate MkDocs config analysis statistics."""

    config_files: int
    findings: int
    plugins: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class MkDocsAnalyzer:
    """Audit MkDocs configuration files for security risks and documentation best practices.

    Scans mkdocs.yml for HTTP site URLs, publicly bound dev servers, secrets in config,
    unpinned plugin dependencies, and dangerous plugin hooks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MkDocsFinding] | None = None
        self._stats: MkDocsStats | None = None
        self._infos: list[MkDocsInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return MkDocs config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("mkdocs.y*ml")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MkDocsFinding], MkDocsInfo]:
        findings: list[MkDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MkDocsInfo(path=rel)

        info = MkDocsInfo(path=rel, lines=len(raw_lines))
        in_plugins = False
        plugins_indent = 0
        current_plugin: MkDocsPluginInfo | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("site_name:"):
                info.site_name = line.split(":", 1)[1].strip().strip("'\"")
                continue

            if line.startswith("site_url:"):
                info.site_url = line.split(":", 1)[1].strip().strip("'\"")
                if HTTP_SITE_URL_PATTERN.match(raw):
                    findings.append(
                        MkDocsFinding(
                            kind="http_site_url",
                            severity="medium",
                            message="site_url uses http:// — prefer https:// for production docs",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if line == "nav:" or line.startswith("nav:"):
                info.has_nav = True
                continue

            if line.startswith("plugins:"):
                in_plugins = True
                plugins_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    for item in inline[1:-1].split(","):
                        name = item.strip().strip("'\"")
                        if name:
                            info.plugins.append(MkDocsPluginInfo(name=name))
                    in_plugins = False
                continue

            if in_plugins:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= plugins_indent and not line.startswith("-"):
                    in_plugins = False
                    current_plugin = None
                elif line.startswith("- "):
                    plugin_name = line[2:].strip().strip("'\"")
                    if ":" in plugin_name:
                        plugin_name = plugin_name.split(":")[0].strip().strip("'\"")
                    current_plugin = MkDocsPluginInfo(name=plugin_name)
                    info.plugins.append(current_plugin)
                    if UNPINNED_PLUGIN_PATTERN.match(line):
                        findings.append(
                            MkDocsFinding(
                                kind="unpinned_plugin_dep",
                                severity="low",
                                message=f"plugin dependency '{plugin_name}' appears unpinned in config",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    continue
                elif current_plugin and ":" in line:
                    key = line.split(":", 1)[0].strip()
                    current_plugin.options.append(key)

            if DEV_ADDR_PUBLIC_PATTERN.match(raw):
                findings.append(
                    MkDocsFinding(
                        kind="public_dev_addr",
                        severity="high",
                        message="dev_addr binds to all interfaces — use 127.0.0.1 for local preview",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_IN_CONFIG_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret hardcoded in MkDocs config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EXEC_IN_PLUGIN_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="dangerous_plugin_hook",
                        severity="high",
                        message="config references exec/subprocess — review for code injection risk",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if REMOTE_CONTENT_PATTERN.search(line) and "true" in line.lower():
                findings.append(
                    MkDocsFinding(
                        kind="remote_content",
                        severity="medium",
                        message="remote content fetching enabled — verify trusted sources only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.site_url and not info.has_nav:
            findings.append(
                MkDocsFinding(
                    kind="missing_nav",
                    severity="low",
                    message="no nav section defined — documentation structure may be unclear",
                    path=rel,
                    lineno=0,
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

        total_plugins = sum(len(i.plugins) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = MkDocsStats(
            config_files=len(paths),
            findings=len(findings),
            plugins=total_plugins,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MkDocsStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MkDocsInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
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
site_name: My Project
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/

theme:
  name: material
  palette:
    primary: indigo

plugins:
  - search
  - mkdocstrings:
      handlers:
        python:
          options:
            show_source: true

nav:
  - Home: index.md
  - API: api/

markdown_extensions:
  - admonition
  - toc:
      permalink: true

# Local preview only — do not bind to 0.0.0.0
dev_addr: 127.0.0.1:8000
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "MkDocs: no config files found"
        return (
            f"MkDocs: {stats.config_files} config(s), {stats.plugins} plugin(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "MkDocs configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  plugins: {stats.plugins}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            site = info.site_name or "unnamed"
            url = info.site_url or "no site_url"
            lines.append(f"  - {info.path}: {site} @ {url}")
            for plugin in info.plugins[:10]:
                opts = ", ".join(plugin.options[:3]) or "default"
                lines.append(f"      plugin: {plugin.name} ({opts})")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
