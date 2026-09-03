"""DocusaurusAnalyzer — audit docusaurus.config.* for documentation security risks."""

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
    "@docusaurus",
    "preset-classic",
    "themeConfig",
    "docusaurus.config",
    "@type {import('@docusaurus",
    "require('@docusaurus",
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
    r"(?:url|editUrl|edit_uri|repo_url|site_url)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
ALGOLIA_ADMIN_KEY_PATTERN = re.compile(
    r"apiKey\s*:\s*['\"][a-f0-9]{32}['\"]",
    re.IGNORECASE,
)
BROKEN_LINKS_IGNORE_PATTERN = re.compile(
    r"onBrokenLinks\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
BROKEN_MARKDOWN_IGNORE_PATTERN = re.compile(
    r"onBrokenMarkdownLinks\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"^\s*(?:scripts|headTags)\s*:\s*\[(?!\s*\])",
    re.IGNORECASE,
)
REMOTE_SCRIPT_ITEM_PATTERN = re.compile(
    r"['\"]https?://[^'\"]+['\"]",
    re.IGNORECASE,
)
INLINE_SCRIPT_PATTERN = re.compile(
    r"tagName\s*:\s*['\"]script['\"]",
    re.IGNORECASE,
)
DANGEROUS_MARKDOWN_PATTERN = re.compile(
    r"dangerouslySetInnerHTML|MDXComponents\s*:\s*\{",
    re.IGNORECASE,
)
CUSTOM_FIELDS_SECRET_PATTERN = re.compile(
    r"customFields\s*:\s*\{[^\}]*(?:secret|token|api[_-]?key)",
    re.IGNORECASE,
)
GA_INLINE_PATTERN = re.compile(
    r"(?:googleAnalytics|gtag)\s*:\s*\{[^\}]*trackingID\s*:\s*['\"][A-Z]{2}-",
    re.IGNORECASE,
)
CLIENT_MODULES_REMOTE_PATTERN = re.compile(
    r"clientModules\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
PLUGIN_REMOTE_PATTERN = re.compile(
    r"(?:plugins|themes)\s*:\s*\[[^\]]*https?://",
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
    has_algolia: bool = False
    has_scripts: bool = False
    has_plugins: bool = False


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


def _is_docusaurus_file(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_docusaurus_config(content)


class DocusaurusAnalyzer:
    """Audit Docusaurus configuration for documentation security risks.

    Scans docusaurus.config.js/ts for hardcoded secrets, Algolia admin keys,
    remote scripts, relaxed link validation, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocusaurusFinding] | None = None
        self._stats: DocusaurusStats | None = None
        self._infos: list[DocusaurusInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Docusaurus configuration paths found in the project."""
        found: list[Path] = []
        preferred_dirs = ("website", "docs-site", "documentation", ".")
        for dirname in preferred_dirs:
            base = self.root if dirname == "." else self.root / dirname
            for name in CONFIG_NAMES:
                path = base / name
                if path.is_file() and _is_docusaurus_file(path) and path not in found:
                    found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_docusaurus_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DocusaurusFinding],
        info: DocusaurusInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped:
            return section

        if "algolia" in stripped.lower() and ("{" in stripped or ":" in stripped):
            section = "algolia"
            info.has_algolia = True
        elif stripped in ("},", "}") and section == "algolia":
            section = ""

        if stripped.startswith("title:") or re.search(r"title\s*:\s*['\"]", stripped):
            match = re.search(r"title\s*:\s*['\"]([^'\"]+)['\"]", stripped)
            if match:
                info.title = match.group(1)

        if "scripts" in stripped and ("[" in stripped or ":" in stripped):
            info.has_scripts = True

        if "plugins" in stripped and ("[" in stripped or ":" in stripped):
            info.has_plugins = True

        if stripped.startswith("scripts:") or stripped.startswith("headTags:"):
            section = stripped.split(":")[0].strip()
            info.has_scripts = True

        if section in ("scripts", "headTags") and REMOTE_SCRIPT_ITEM_PATTERN.search(stripped):
            findings.append(
                DocusaurusFinding(
                    kind="remote_script",
                    severity="high",
                    message="remote script URL in scripts/headTags — self-host or pin with SRI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif stripped in ("]", "],") and section in ("scripts", "headTags"):
            section = ""

        if section == "algolia" and ALGOLIA_ADMIN_KEY_PATTERN.search(stripped):
            findings.append(
                DocusaurusFinding(
                    kind="algolia_admin_key",
                    severity="high",
                    message="Algolia apiKey in client config — use search-only key and env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Docusaurus config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Docusaurus config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Docusaurus config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (BROKEN_LINKS_IGNORE_PATTERN, "broken_links_ignore", "medium", "onBrokenLinks: 'ignore' hides broken links — use 'throw' or 'warn'"),
            (BROKEN_MARKDOWN_IGNORE_PATTERN, "broken_markdown_ignore", "medium", "onBrokenMarkdownLinks: 'ignore' hides broken markdown links — use 'throw'"),
            (EXTERNAL_SCRIPT_PATTERN, "external_scripts", "medium", "scripts/headTags section present — review third-party script sources"),
            (INLINE_SCRIPT_PATTERN, "inline_script_tag", "medium", "headTags includes inline script tag — avoid client-side injection vectors"),
            (DANGEROUS_MARKDOWN_PATTERN, "dangerous_markdown", "high", "dangerouslySetInnerHTML or custom MDX — review for XSS risk"),
            (CUSTOM_FIELDS_SECRET_PATTERN, "custom_fields_secret", "high", "customFields may expose secrets to client bundle — use server-side env"),
            (GA_INLINE_PATTERN, "inline_analytics", "low", "inline Google Analytics config — load via tag manager with consent"),
            (CLIENT_MODULES_REMOTE_PATTERN, "remote_client_module", "high", "clientModules references remote URL — only load trusted local modules"),
            (PLUGIN_REMOTE_PATTERN, "remote_plugin", "high", "plugins/themes reference remote URL — only load trusted npm packages"),
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

        return section

    def _analyze_file(self, path: Path) -> tuple[list[DocusaurusFinding], DocusaurusInfo]:
        findings: list[DocusaurusFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DocusaurusInfo(path=rel)

        info = DocusaurusInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

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
        """Scaffold a hardened docusaurus.config.js template."""
        return """\
// Generated by DevAI DocusaurusAnalyzer
/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'My Project',
  tagline: 'Documentation',
  url: 'https://example.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  favicon: 'img/favicon.ico',
  organizationName: 'org',
  projectName: 'repo',
  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/org/repo/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
  themeConfig: {
    navbar: {
      title: 'My Project',
      items: [{ type: 'docSidebar', sidebarId: 'tutorialSidebar', label: 'Docs' }],
    },
    // Use search-only Algolia key via env: process.env.ALGOLIA_SEARCH_KEY
    // algolia: { appId: '...', apiKey: process.env.ALGOLIA_SEARCH_KEY },
  },
  // Self-host scripts; do not load remote third-party URLs here
  scripts: [],
  headTags: [],
  customFields: {},
};

module.exports = config;
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
