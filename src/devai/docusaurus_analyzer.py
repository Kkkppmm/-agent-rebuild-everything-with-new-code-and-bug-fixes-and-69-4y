"""DocusaurusAnalyzer — audit docusaurus.config.* for documentation security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "docusaurus.config.js",
    "docusaurus.config.ts",
    "docusaurus.config.mjs",
    "docusaurus.config.cjs",
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
    r"(?:url|baseUrl|editUrl|repoUrl)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
BROKEN_LINKS_RELAXED_PATTERN = re.compile(
    r"onBroken(?:Links|MarkdownLinks)\s*:\s*['\"]?(?:warn|ignore)['\"]?",
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
DANGEROUS_HTML_PATTERN = re.compile(
    r"(?:dangerouslySetInnerHTML|allowDangerousHtml|dangerouslyAllowSVG)\s*:\s*true",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:scripts|clientModules|headTags)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE | re.DOTALL,
)
REMOTE_STYLESHEET_PATTERN = re.compile(
    r"stylesheets\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE | re.DOTALL,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
CUSTOM_FIELDS_SECRET_PATTERN = re.compile(
    r"customFields\s*:\s*\{[^}]*(?:password|secret|api[_-]?key|token)\s*:",
    re.IGNORECASE | re.DOTALL,
)
REHYPE_RAW_PATTERN = re.compile(
    r"rehype-raw|allowDangerousHtml",
    re.IGNORECASE,
)
TRAILING_SLASH_FALSE_PATTERN = re.compile(
    r"trailingSlash\s*:\s*false",
    re.IGNORECASE,
)
OPENAPI_UNSAFE_PATTERN = re.compile(
    r"(?:specPath|proxy)\s*:\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
GTAG_INLINE_PATTERN = re.compile(
    r"(?:googleAnalytics|gtag)\s*:\s*\{[^}]*trackingID\s*:\s*['\"][A-Z]{2}-",
    re.IGNORECASE | re.DOTALL,
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
    file_kind: str = ""
    has_presets: bool = False
    has_plugins: bool = False
    has_theme_config: bool = False
    has_algolia: bool = False


@dataclass
class DocusaurusStats:
    """Aggregate Docusaurus analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_docusaurus_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith("docusaurus.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts"):
        return "typescript"
    if name.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    return "unknown"


def _looks_like_docusaurus_project(root: Path) -> bool:
    if any((root / name).exists() for name in CONFIG_NAMES):
        return True
    if any(root.glob("docusaurus.config.*")):
        return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            for section in ("dependencies", "devDependencies"):
                deps = data.get(section, {})
                if isinstance(deps, dict) and (
                    "@docusaurus/core" in deps or "docusaurus" in deps
                ):
                    return True
        except json.JSONDecodeError:
            pass
    return False


class DocusaurusAnalyzer:
    """Audit Docusaurus configuration for documentation security and hygiene risks.

    Scans docusaurus.config.* for hardcoded secrets, Algolia API keys, exposed
    dev servers, relaxed broken-link checks, remote scripts, and unsafe HTML.
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
            if path.is_file():
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
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if "presets:" in stripped or "presets :" in stripped:
            info.has_presets = True
        if "plugins:" in stripped or "plugins :" in stripped:
            info.has_plugins = True
        if "themeConfig:" in stripped or "themeConfig :" in stripped:
            info.has_theme_config = True
        if "algolia" in stripped.lower():
            info.has_algolia = True

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Docusaurus config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Docusaurus config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Docusaurus config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CREDENTIAL_IN_URL_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="credential_in_url",
                    severity="high",
                    message="credentials embedded in url/repoUrl — remove user:pass@",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROKEN_LINKS_RELAXED_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="broken_links_relaxed",
                    severity="medium",
                    message="onBrokenLinks/onBrokenMarkdownLinks set to warn/ignore — use 'throw' in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HOST_EXPOSED_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="host_exposed",
                    severity="medium",
                    message="dev server binds to all interfaces — use localhost for local dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALGOLIA_HARDCODED_KEY_PATTERN.search(line) and "search" in line.lower():
            findings.append(
                DocusaurusFinding(
                    kind="algolia_hardcoded_key",
                    severity="high",
                    message="Algolia apiKey hardcoded — use env vars and restrict search-only keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_HTML_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="dangerous_html",
                    severity="high",
                    message="dangerous HTML rendering enabled — sanitize user content",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_SCRIPT_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="remote_script",
                    severity="medium",
                    message="remote script in scripts/clientModules — self-host or pin with SRI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_STYLESHEET_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="remote_stylesheet",
                    severity="low",
                    message="remote stylesheet — self-host or pin version",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval() in Docusaurus config — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CUSTOM_FIELDS_SECRET_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="custom_fields_secret",
                    severity="high",
                    message="secret in customFields — use env vars instead of embedding credentials",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REHYPE_RAW_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="rehype_raw",
                    severity="medium",
                    message="rehype-raw or allowDangerousHtml — only enable for trusted content",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRAILING_SLASH_FALSE_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="trailing_slash_false",
                    severity="low",
                    message="trailingSlash: false can cause duplicate-content SEO issues",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OPENAPI_UNSAFE_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="openapi_remote_spec",
                    severity="medium",
                    message="remote OpenAPI spec URL — vendor spec locally to avoid supply-chain risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GTAG_INLINE_PATTERN.search(line):
            findings.append(
                DocusaurusFinding(
                    kind="gtag_inline",
                    severity="low",
                    message="inline Google Analytics config — prefer env-based plugin configuration",
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
            return findings, DocusaurusInfo(path=rel, file_kind=_file_kind(path))

        info = DocusaurusInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

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
  title: 'My Project',
  tagline: 'Documentation',
  favicon: 'img/favicon.ico',
  url: 'https://example.com',
  baseUrl: '/',
  organizationName: 'org',
  projectName: 'repo',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  trailingSlash: true,

  presets: [
    [
      'classic',
      {
        docs: {
          editUrl: 'https://github.com/org/repo/tree/main/',
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
      items: [{type: 'docSidebar', sidebarId: 'tutorialSidebar', label: 'Docs'}],
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
    // Use env vars for Algolia — never commit search-only keys in plaintext
    // algolia: {
    //   appId: process.env.ALGOLIA_APP_ID,
    //   apiKey: process.env.ALGOLIA_SEARCH_KEY,
    //   indexName: 'docs',
    // },
  },

  // Self-host assets; avoid remote scripts without SRI
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
