"""VitePressAnalyzer — audit .vitepress/config.* for documentation security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "config.js",
    "config.ts",
    "config.mjs",
    "config.cjs",
)
VITEPRESS_DIR = ".vitepress"
VITEPRESS_MARKERS = (
    "vitepress",
    "themeconfig",
    "themeConfig",
    "markdown",
    "head",
    "sitemap",
    "transformhead",
    "transformHead",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|search[_-]?api[_-]?key)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:hostname|base|editLink|repo)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
MARKDOWN_UNSAFE_PATTERN = re.compile(
    r"(?:html|unsafe)\s*:\s*true",
    re.IGNORECASE,
)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:host|hostname)\s*:\s*(?:['\"]0\.0\.0\.0['\"]|['\"]::['\"]|true)",
    re.IGNORECASE,
)
ALGOLIA_HARDCODED_KEY_PATTERN = re.compile(
    r"apiKey\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:head|scripts|clientModules)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE | re.DOTALL,
)
REMOTE_STYLE_PATTERN = re.compile(
    r"(?:head|styles)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE | re.DOTALL,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
DANGEROUS_HTML_PATTERN = re.compile(
    r"(?:dangerouslySetInnerHTML|allowDangerousHtml)\s*:\s*true",
    re.IGNORECASE,
)
SITEMAP_HTTP_PATTERN = re.compile(
    r"sitemap\s*:\s*\{[^}]*hostname\s*:\s*['\"]http://",
    re.IGNORECASE | re.DOTALL,
)
GTAG_INLINE_PATTERN = re.compile(
    r"(?:gtag|googleAnalytics)\s*:\s*\{[^}]*(?:id|measurementId)\s*:\s*['\"][A-Z]{2}-",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class VitePressFinding:
    """A security or best-practice issue in a VitePress configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class VitePressInfo:
    """Parsed metadata about a VitePress configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    has_theme_config: bool = False
    has_algolia: bool = False
    has_sitemap: bool = False


@dataclass
class VitePressStats:
    """Aggregate VitePress analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_vitepress_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in VITEPRESS_MARKERS)


def _is_vitepress_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    if VITEPRESS_DIR not in path.parts:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_vitepress_config(content)


class VitePressAnalyzer:
    """Audit VitePress configuration for documentation security and hygiene risks.

    Scans .vitepress/config.* for Algolia keys, markdown.unsafe, remote scripts,
    exposed dev servers, and hardcoded secrets in themeConfig.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitePressFinding] | None = None
        self._stats: VitePressStats | None = None
        self._infos: list[VitePressInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return VitePress configuration paths found in the project."""
        found: list[Path] = []
        preferred_dirs = (
            self.root / ".vitepress",
            self.root / "docs" / ".vitepress",
        )
        for base in preferred_dirs:
            if not base.is_dir():
                continue
            for name in CONFIG_NAMES:
                path = base / name
                if path.is_file() and _is_vitepress_config(path):
                    found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_vitepress_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[VitePressFinding],
        info: VitePressInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return section

        if "themeConfig" in stripped:
            info.has_theme_config = True
            section = "themeConfig"
        if "algolia" in stripped.lower():
            info.has_algolia = True
        if "sitemap" in stripped.lower():
            info.has_sitemap = True

        if stripped.startswith("title:") or stripped.startswith("title "):
            info.title = stripped.split(":", 1)[-1].strip().strip("'\"")

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in VitePress config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in VitePress config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in VitePress config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (MARKDOWN_UNSAFE_PATTERN, "markdown_unsafe", "high", "markdown.html/unsafe enabled — raw HTML injection risk in docs"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium", "dev server binds to all interfaces — restrict to localhost"),
            (ALGOLIA_HARDCODED_KEY_PATTERN, "algolia_hardcoded_key", "high", "Algolia apiKey hardcoded — use env vars and server-side search proxy"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium", "head/scripts loads remote script — pin version and self-host assets"),
            (REMOTE_STYLE_PATTERN, "remote_stylesheet", "medium", "head/styles loads remote stylesheet — self-host assets"),
            (EVAL_PATTERN, "eval_usage", "high", "eval() in VitePress config — avoid dynamic code execution"),
            (DANGEROUS_HTML_PATTERN, "dangerous_html", "high", "dangerouslySetInnerHTML enabled — XSS risk in documentation"),
            (SITEMAP_HTTP_PATTERN, "sitemap_http", "medium", "sitemap hostname uses HTTP — use HTTPS canonical URLs"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    VitePressFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if GTAG_INLINE_PATTERN.search(line):
            findings.append(
                VitePressFinding(
                    kind="gtag_inline",
                    severity="low",
                    message="Google Analytics ID in config — prefer env-based injection for multi-env builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[VitePressFinding], VitePressInfo]:
        findings: list[VitePressFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, VitePressInfo(path=rel)

        info = VitePressInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def analyze(self) -> list[VitePressFinding]:
        """Scan VitePress configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VitePressFinding] = []
        infos: list[VitePressInfo] = []
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
        self._stats = VitePressStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VitePressStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VitePressInfo]:
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
        """Scaffold a hardened VitePress config template."""
        return """\
// Generated by DevAI VitePressAnalyzer
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'My Project',
  description: 'Project documentation',
  base: '/',
  head: [],
  markdown: {
    html: false,
  },
  themeConfig: {
    nav: [{ text: 'Guide', link: '/guide/' }],
    sidebar: [{ text: 'Introduction', link: '/guide/' }],
    socialLinks: [],
    search: {
      provider: 'local',
    },
  },
  sitemap: {
    hostname: 'https://example.com',
  },
})
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "VitePress configs: none found"
        return (
            f"VitePress configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "VitePress analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
