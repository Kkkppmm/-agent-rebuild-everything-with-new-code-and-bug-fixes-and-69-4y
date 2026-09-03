"""DocusaurusAnalyzer — audit docusaurus.config.* for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "docusaurus.config.js",
    "docusaurus.config.ts",
    "docusaurus.config.mjs",
    "docusaurus.config.cjs",
)

DOCUSAURUS_MARKERS = (
    "docusaurus",
    "preset-classic",
    "themeConfig",
    "onBrokenLinks",
    "url:",
    "baseUrl",
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
    r"(?:url|editUrl|organizationName|projectName)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
CUSTOM_FIELDS_SECRET_PATTERN = re.compile(
    r"(?:customFields\s*:\s*\{[^\}]*(?:secret|token|apiKey|password)|"
    r"(?:apiSecret|apiKey|secretKey|authToken)\s*:\s*['\"])",
    re.IGNORECASE,
)
REMOTE_SCRIPT_SRC_PATTERN = re.compile(
    r"src\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"scripts\s*:\s*\[[^\]]*src\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_STYLE_PATTERN = re.compile(
    r"stylesheets\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
IGNORE_BROKEN_LINKS_PATTERN = re.compile(
    r"onBrokenLinks\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"debug\s*:\s*true",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec|Function)\s*\(", re.IGNORECASE)
WEBPACK_EVAL_PATTERN = re.compile(
    r"devtool\s*:\s*['\"]eval",
    re.IGNORECASE,
)
CLIENT_MODULES_REMOTE_PATTERN = re.compile(
    r"clientModules\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
DANGEROUS_REMARK_PLUGIN_PATTERN = re.compile(
    r"(?:rehype-raw|allowDangerousHtml)\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class DocusaurusFinding:
    """A security or best-practice issue in a Docusaurus configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DocusaurusInfo:
    """Parsed metadata about a Docusaurus configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    url: str | None = None
    has_theme_config: bool = False
    has_scripts: bool = False


@dataclass
class DocusaurusStats:
    """Aggregate Docusaurus analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_docusaurus_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in DOCUSAURUS_MARKERS)


def _is_docusaurus_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_docusaurus_config(content)


class DocusaurusAnalyzer:
    """Audit Docusaurus configuration for documentation security and hygiene risks.

    Scans docusaurus.config.* for hardcoded secrets, remote scripts/stylesheets,
    ignored broken links, debug mode, and dangerous remark/rehype plugins.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocusaurusFinding] | None = None
        self._stats: DocusaurusStats | None = None
        self._infos: list[DocusaurusInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Docusaurus configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_docusaurus_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("docusaurus.config.*")):
            if path.is_file() and _is_docusaurus_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DocusaurusFinding],
        info: DocusaurusInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if stripped.startswith("title:") or stripped.startswith("title :"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\",")

        if stripped.startswith("url:") or stripped.startswith("url :"):
            info.url = stripped.split(":", 1)[1].strip().strip("'\",")

        if "themeConfig" in stripped:
            info.has_theme_config = True

        if "scripts:" in stripped or "scripts :" in stripped:
            info.has_scripts = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Docusaurus config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Docusaurus config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Docusaurus config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (CUSTOM_FIELDS_SECRET_PATTERN, "custom_fields_secret", "high", "customFields exposes secret to client bundle — use server-side env vars"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium", "scripts loads remote script — pin version and self-host assets"),
            (REMOTE_SCRIPT_SRC_PATTERN, "remote_script", "medium", "scripts loads remote script — pin version and self-host assets"),
            (REMOTE_STYLE_PATTERN, "remote_stylesheet", "low", "stylesheets loads remote stylesheet — pin version or self-host assets"),
            (IGNORE_BROKEN_LINKS_PATTERN, "ignore_broken_links", "low", "onBrokenLinks: ignore — broken links may go unnoticed"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium", "debug: true exposes verbose build info — disable in production"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Docusaurus config — avoid dynamic code execution in config"),
            (WEBPACK_EVAL_PATTERN, "webpack_eval", "medium", "webpack devtool uses eval — avoid in production builds"),
            (CLIENT_MODULES_REMOTE_PATTERN, "client_modules_remote", "medium", "clientModules loads remote module — pin to trusted package"),
            (REMOTE_SCRIPT_SRC_PATTERN, "client_modules_remote", "medium", "clientModules loads remote module — pin to trusted package"),
            (DANGEROUS_REMARK_PLUGIN_PATTERN, "dangerous_remark_plugin", "high", "rehype-raw/allowDangerousHtml enabled — XSS risk in rendered content"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    DocusaurusFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[DocusaurusFinding], DocusaurusInfo]:
        findings: list[DocusaurusFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DocusaurusInfo(path=rel)

        info = DocusaurusInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[DocusaurusFinding]:
        """Scan Docusaurus configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DocusaurusFinding] = []
        infos: list[DocusaurusInfo] = []
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
        self._stats = DocusaurusStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DocusaurusStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DocusaurusInfo]:
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
        """Scaffold a hardened Docusaurus configuration template."""
        return """\
// Generated by DevAI DocusaurusAnalyzer
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'My Project Docs',
  tagline: 'Documentation for my project',
  url: 'https://example.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  organizationName: 'org',
  projectName: 'repo',

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/org/repo/edit/main/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      },
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'My Project Docs',
      items: [{type: 'docSidebar', sidebarId: 'tutorialSidebar', label: 'Docs'}],
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },

  // Self-host assets instead of loading remote scripts/stylesheets
  scripts: [],
  stylesheets: [],
};

export default config;
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Docusaurus configs: none found"
        return (
            f"Docusaurus configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Docusaurus analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
