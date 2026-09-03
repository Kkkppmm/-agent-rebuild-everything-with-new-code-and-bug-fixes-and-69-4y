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
    "@docusaurus",
    "themeConfig",
    "onBrokenLinks",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|algoliaApiKey)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:url|baseUrl|editUrl|repoUrl|deploymentBranchUrl)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|Function)\s*\(", re.IGNORECASE)
CHILD_PROCESS_PATTERN = re.compile(
    r"(?:child_process|execSync|spawnSync|exec\(|spawn\()",
    re.IGNORECASE,
)
BROKEN_LINKS_IGNORE_PATTERN = re.compile(
    r"onBroken(?:Links|MarkdownLinks)\s*:\s*['\"]?(?:ignore|warn)['\"]?",
    re.IGNORECASE,
)
ALGOLIA_ADMIN_KEY_PATTERN = re.compile(
    r"apiKey\s*:\s*['\"][a-f0-9]{32,}['\"]",
    re.IGNORECASE,
)
DANGEROUS_HTML_PATTERN = re.compile(
    r"dangerouslySetInnerHTML|rehypeRaw|allowDangerousHtml\s*:\s*true",
    re.IGNORECASE,
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"(?:scripts|headTags|stylesheets)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
CUSTOM_FIELDS_SECRET_PATTERN = re.compile(
    r"customFields\s*:\s*\{[^\}]*(?:password|secret|api[_-]?key|token)",
    re.IGNORECASE,
)
PARENT_PATH_PATTERN = re.compile(
    r"(?:path|dir|localeDir|blogDir|pagesDir|docsDir)\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)
WEBPACK_UNSAFE_PATTERN = re.compile(
    r"configureWebpack|webpack\(|chainWebpack",
    re.IGNORECASE,
)
RUNTIME_ENV_EXPOSED_PATTERN = re.compile(
    r"customFields\s*:\s*\{[^\}]*process\.env\.[A-Z_]+",
    re.IGNORECASE,
)
TRAILING_SLASH_FALSE_PATTERN = re.compile(
    r"trailingSlash\s*:\s*false",
    re.IGNORECASE,
)
EDIT_URL_HTTP_PATTERN = re.compile(
    r"editUrl\s*:\s*['\"]http://",
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
    base_url: str | None = None
    has_algolia: bool = False
    has_custom_fields: bool = False


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
    """Audit Docusaurus config files for documentation security and hygiene risks.

    Scans docusaurus.config.js/ts/mjs for hardcoded secrets, Algolia key exposure,
    unsafe markdown/HTML settings, broken-link suppression, and remote asset loading.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocusaurusFinding] | None = None
        self._stats: DocusaurusStats | None = None
        self._infos: list[DocusaurusInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Docusaurus config paths found in the project."""
        found: list[Path] = []
        preferred_dirs = ("website", "docs-site", "docusaurus", ".")
        for dirname in preferred_dirs:
            base = self.root if dirname == "." else self.root / dirname
            for name in CONFIG_NAMES:
                path = base / name
                if path.is_file() and _is_docusaurus_config(path) and path not in found:
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
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return section

        if stripped.startswith(("scripts:", "headTags:", "stylesheets:")):
            section = "assets"
        elif stripped in ("],", "]") and section == "assets":
            section = ""

        if "customFields" in stripped and "{" in stripped:
            section = "custom_fields"
        elif stripped.startswith("}") and section == "custom_fields":
            section = ""

        if stripped.startswith("title:") or stripped.startswith("title :"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\",")

        if stripped.startswith("url:") or stripped.startswith("url :"):
            info.url = stripped.split(":", 1)[1].strip().strip("'\",")

        if stripped.startswith("baseUrl:") or stripped.startswith("baseUrl :"):
            info.base_url = stripped.split(":", 1)[1].strip().strip("'\",")

        if "algolia" in stripped.lower():
            info.has_algolia = True

        if "customFields" in stripped:
            info.has_custom_fields = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (
                HARDCODED_SECRET_PATTERN,
                "hardcoded_secret",
                "high",
                "hardcoded secret in Docusaurus config — use env vars or CI secrets",
            ),
            (
                AWS_ACCESS_KEY_PATTERN,
                "aws_access_key",
                "high",
                "AWS access key in Docusaurus config — rotate and use env vars",
            ),
            (
                INSECURE_HTTP_PATTERN,
                "insecure_http",
                "medium",
                "insecure HTTP URL in Docusaurus config — use HTTPS endpoints",
            ),
            (
                CREDENTIAL_IN_URL_PATTERN,
                "credential_in_url",
                "high",
                "credentials embedded in URL setting — remove user:pass@",
            ),
            (
                EVAL_EXEC_PATTERN,
                "eval_exec",
                "high",
                "eval/Function in Docusaurus config — avoid dynamic code execution",
            ),
            (
                CHILD_PROCESS_PATTERN,
                "shell_execution",
                "high",
                "child_process/shell call in Docusaurus config — avoid command execution",
            ),
            (
                BROKEN_LINKS_IGNORE_PATTERN,
                "broken_links_ignored",
                "medium",
                "onBrokenLinks/onBrokenMarkdownLinks set to ignore/warn — use 'throw' in CI",
            ),
            (
                ALGOLIA_ADMIN_KEY_PATTERN,
                "algolia_admin_key",
                "high",
                "Algolia admin/search API key in client config — use search-only key",
            ),
            (
                DANGEROUS_HTML_PATTERN,
                "dangerous_html",
                "high",
                "dangerous HTML/raw markdown enabled — sanitize user content",
            ),
            (
                PARENT_PATH_PATTERN,
                "parent_path",
                "medium",
                "config path references parent directory — restrict to project paths",
            ),
            (
                WEBPACK_UNSAFE_PATTERN,
                "webpack_customization",
                "low",
                "custom webpack config — review for supply-chain and injection risks",
            ),
            (
                TRAILING_SLASH_FALSE_PATTERN,
                "trailing_slash_false",
                "low",
                "trailingSlash: false can cause duplicate-content SEO issues",
            ),
            (
                EDIT_URL_HTTP_PATTERN,
                "edit_url_http",
                "medium",
                "editUrl uses HTTP — use HTTPS for edit links",
            ),
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

        if section == "assets" and re.search(r"https?://", stripped):
            findings.append(
                DocusaurusFinding(
                    kind="external_asset",
                    severity="medium",
                    message="remote script/stylesheet loaded — pin version and self-host assets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "custom_fields":
            if re.search(
                r"(?:password|secret|api[_-]?key|token)\s*:\s*['\"][^'\"]+['\"]",
                stripped,
                re.IGNORECASE,
            ):
                findings.append(
                    DocusaurusFinding(
                        kind="custom_fields_secret",
                        severity="high",
                        message="customFields exposes secret-like values to client bundle",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if re.search(r"process\.env\.[A-Z_]+", stripped):
                findings.append(
                    DocusaurusFinding(
                        kind="env_exposed_to_client",
                        severity="high",
                        message="process.env value exposed via customFields — only expose public vars",
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
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'My Project',
  tagline: 'Documentation',
  favicon: 'img/favicon.ico',
  url: 'https://docs.example.com',
  baseUrl: '/',
  organizationName: 'my-org',
  projectName: 'my-project',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  trailingSlash: true,

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/my-org/my-project/tree/main/website/',
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
      title: 'My Project',
      items: [
        {type: 'docSidebar', sidebarId: 'tutorialSidebar', label: 'Docs'},
      ],
    },
    footer: {
      style: 'dark',
      copyright: `Copyright © ${new Date().getFullYear()} My Organization.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },
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
