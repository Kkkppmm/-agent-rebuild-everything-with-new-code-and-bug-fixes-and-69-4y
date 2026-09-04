"""JekyllAnalyzer — audit Jekyll _config.yml for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "_config.yml",
    "_config.yaml",
    "_config.toml",
)

JEKYLL_MARKERS = (
    "baseurl",
    "jekyll",
    "plugins",
    "markdown",
    "title",
    "url",
    "theme",
    "collections",
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
    r"(?:baseurl|url|repo_url|edit_uri)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
HOST_ALL_INTERFACES_PATTERN = re.compile(
    r"^\s*host\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
SAFE_FALSE_PATTERN = re.compile(r"^\s*safe\s*:\s*false\b", re.IGNORECASE)
DANGEROUS_PLUGIN_PATTERN = re.compile(
    r"(?:jekyll-(?:exec|execute|shell|rubycode)|rubycode|shellcmd)",
    re.IGNORECASE,
)
REMOTE_THEME_PATTERN = re.compile(
    r"(?:remote_theme|theme)\s*:\s*[^\n]*https?://",
    re.IGNORECASE,
)
REMOTE_INCLUDE_PATTERN = re.compile(
    r"(?:include|include_remote|gems)\s*:.*https?://",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:head_scripts|footer_scripts|custom_js|scripts)\s*:.*https?://",
    re.IGNORECASE,
)
REMOTE_SCRIPT_LIST_PATTERN = re.compile(
    r"^\s*-\s+https?://[^\s\"']*\.js",
    re.IGNORECASE,
)
REMOTE_STYLE_PATTERN = re.compile(
    r"(?:head_styles|custom_css|stylesheets)\s*:.*https?://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
LIVERELOAD_ALL_PATTERN = re.compile(
    r"(?:livereload|watch)\s*:\s*true",
    re.IGNORECASE,
)
DISABLED_HIGHLIGHTER_PATTERN = re.compile(
    r"^\s*highlighter\s*:\s*(?:null|none)\b",
    re.IGNORECASE,
)


@dataclass
class JekyllFinding:
    """A security or best-practice issue in a Jekyll configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JekyllInfo:
    """Parsed metadata about a Jekyll configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    base_url: str | None = None
    theme: str | None = None
    plugins: list[str] = field(default_factory=list)


@dataclass
class JekyllStats:
    """Aggregate Jekyll analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_jekyll_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in JEKYLL_MARKERS)


def _is_jekyll_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_jekyll_config(content)


class JekyllAnalyzer:
    """Audit Jekyll configuration for documentation security and hygiene risks.

    Scans _config.yml for hardcoded secrets, exposed dev servers, unsafe plugins,
    disabled safe mode, remote theme/includes, and insecure base URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JekyllFinding] | None = None
        self._stats: JekyllStats | None = None
        self._infos: list[JekyllInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Jekyll configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_jekyll_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jekyll_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[JekyllFinding],
        info: JekyllInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if ":" in stripped and not stripped.startswith("-"):
            key, _, value = stripped.partition(":")
            key_lower = key.strip().lower()
            value = value.strip().strip("'\"")
            if key_lower == "title":
                info.title = value
            elif key_lower in ("baseurl", "url"):
                info.base_url = value
            elif key_lower in ("theme", "remote_theme"):
                info.theme = value
            elif key_lower == "plugins" and value:
                info.plugins.append(value)

        if stripped.startswith("-") and info.plugins is not None:
            plugin = stripped.lstrip("-").strip().strip("'\"")
            if plugin:
                info.plugins.append(plugin)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Jekyll config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Jekyll config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Jekyll config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in baseurl/url — remove user:pass@"),
            (HOST_ALL_INTERFACES_PATTERN, "bind_all_interfaces", "medium", "host binds to all interfaces — use 127.0.0.1 for local dev"),
            (SAFE_FALSE_PATTERN, "unsafe_safe_mode", "high", "safe: false disables Jekyll safe mode — XSS and arbitrary Liquid risk"),
            (DANGEROUS_PLUGIN_PATTERN, "dangerous_plugin", "high", "dangerous Jekyll plugin — avoid exec/shell plugins in production"),
            (REMOTE_THEME_PATTERN, "remote_theme", "medium", "remote theme loads from URL — pin to trusted source"),
            (REMOTE_INCLUDE_PATTERN, "remote_include", "medium", "remote include/gem source — pin to trusted commit/tag"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium", "head/footer scripts load remote JS — pin version and self-host assets"),
            (REMOTE_SCRIPT_LIST_PATTERN, "remote_script", "medium", "head/footer scripts load remote JS — pin version and self-host assets"),
            (REMOTE_STYLE_PATTERN, "remote_stylesheet", "low", "custom styles load remote CSS — pin version or self-host assets"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Jekyll config — avoid dynamic code execution in config"),
            (LIVERELOAD_ALL_PATTERN, "livereload_enabled", "low", "livereload/watch enabled — ensure host is not exposed publicly"),
            (DISABLED_HIGHLIGHTER_PATTERN, "disabled_highlighter", "low", "syntax highlighter disabled — code blocks may render without highlighting"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    JekyllFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[JekyllFinding], JekyllInfo]:
        findings: list[JekyllFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JekyllInfo(path=rel)

        info = JekyllInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[JekyllFinding]:
        """Scan Jekyll configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JekyllFinding] = []
        infos: list[JekyllInfo] = []
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
        self._stats = JekyllStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JekyllStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JekyllInfo]:
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
        """Scaffold a hardened Jekyll configuration template."""
        return """\
# Generated by DevAI JekyllAnalyzer
title: My Project Docs
url: https://example.com
baseurl: ""
theme: minima

markdown: kramdown
highlighter: rouge
safe: true

host: 127.0.0.1
port: 4000

plugins:
  - jekyll-feed
  - jekyll-seo-tag

# Use env vars for analytics and third-party keys
# google_analytics: ""

# Self-host assets instead of loading remote scripts/stylesheets
head_scripts: []
footer_scripts: []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Jekyll configs: none found"
        return (
            f"Jekyll configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Jekyll analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
