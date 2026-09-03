"""ZolaAnalyzer — audit config.toml for Zola static site security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "config.toml",
    "zola.toml",
)

ZOLA_MARKERS = (
    "base_url",
    "compile_sass",
    "taxonomies",
    "default_language",
    "theme",
    "markdown",
    "slugify",
    "generate_feeds",
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
    r"(?:base_url|feed_filename|taxonomies)\s*=\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
BIND_ALL_INTERFACES_PATTERN = re.compile(
    r"(?:bind|bind_address|interface)\s*=\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
REMOTE_SASS_IMPORT_PATTERN = re.compile(
    r"@import\s+['\"]https?://",
    re.IGNORECASE,
)
REMOTE_EXTRA_HEAD_PATTERN = re.compile(
    r"(?:extra_head|head)\s*=\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
SEARCH_INCLUDE_CONTENT_PATTERN = re.compile(
    r"(?:include_content|index_format)\s*=\s*true",
    re.IGNORECASE,
)
UNSAFE_MARKDOWN_PATTERN = re.compile(
    r"(?:render_emoji|external_links_target_blank)\s*=\s*true",
    re.IGNORECASE,
)
DISABLED_SLUGIFY_PATTERN = re.compile(
    r"slugify\s*=\s*['\"]?off['\"]?",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
REMOTE_THEME_PATTERN = re.compile(
    r"theme\s*=\s*['\"]https?://",
    re.IGNORECASE,
)


@dataclass
class ZolaFinding:
    """A security or best-practice issue in a Zola configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ZolaInfo:
    """Parsed metadata about a Zola configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    base_url: str | None = None
    theme: str | None = None
    has_taxonomies: bool = False


@dataclass
class ZolaStats:
    """Aggregate Zola analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_zola_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in ZOLA_MARKERS)


def _is_zola_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_zola_config(content)


class ZolaAnalyzer:
    """Audit Zola configuration for documentation security and hygiene risks.

    Scans config.toml for hardcoded secrets, exposed dev servers, remote theme
    imports, unsafe markdown settings, and insecure base URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ZolaFinding] | None = None
        self._stats: ZolaStats | None = None
        self._infos: list[ZolaInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Zola configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_zola_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_zola_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ZolaFinding],
        info: ZolaInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if stripped.startswith(("title", "base_url", "theme")) and "=" in stripped:
            key, _, value = stripped.partition("=")
            value = value.strip().strip("'\"")
            key_lower = key.strip().lower()
            if key_lower == "title":
                info.title = value
            elif key_lower == "base_url":
                info.base_url = value
            elif key_lower == "theme":
                info.theme = value

        if stripped.startswith("taxonomies") and "=" in stripped:
            info.has_taxonomies = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Zola config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Zola config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Zola config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in base_url — remove user:pass@"),
            (BIND_ALL_INTERFACES_PATTERN, "bind_all_interfaces", "medium", "server binds to all interfaces — use 127.0.0.1 for local dev"),
            (REMOTE_SASS_IMPORT_PATTERN, "remote_sass_import", "medium", "SASS imports remote stylesheet — self-host or pin trusted sources"),
            (REMOTE_EXTRA_HEAD_PATTERN, "remote_head_asset", "medium", "extra_head loads remote asset — pin version and self-host scripts"),
            (SEARCH_INCLUDE_CONTENT_PATTERN, "search_include_content", "low", "search indexes full page content — verify drafts are excluded"),
            (UNSAFE_MARKDOWN_PATTERN, "unsafe_markdown", "low", "markdown setting may weaken link/tabnabbing protections — review external link policy"),
            (DISABLED_SLUGIFY_PATTERN, "slugify_disabled", "low", "slugify disabled — URL collisions and encoding issues may occur"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Zola config — avoid dynamic code execution in config"),
            (REMOTE_THEME_PATTERN, "remote_theme", "medium", "theme loads from remote URL — pin to trusted commit/tag"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    ZolaFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[ZolaFinding], ZolaInfo]:
        findings: list[ZolaFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ZolaInfo(path=rel)

        info = ZolaInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[ZolaFinding]:
        """Scan Zola configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ZolaFinding] = []
        infos: list[ZolaInfo] = []
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
        self._stats = ZolaStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ZolaStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ZolaInfo]:
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
        """Scaffold a hardened Zola configuration template."""
        return """\
# Generated by DevAI ZolaAnalyzer
base_url = "https://example.com"
title = "My Project Docs"
default_language = "en"
compile_sass = true
build_search_index = true
generate_feeds = true

[markdown]
external_links_target_blank = false
render_emoji = false

[search]
include_content = false
index_format = "elasticlunr_javascript"

[server]
interface = "127.0.0.1"

[extra]
# Use env vars for analytics and third-party keys
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Zola configs: none found"
        return (
            f"Zola configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Zola analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
