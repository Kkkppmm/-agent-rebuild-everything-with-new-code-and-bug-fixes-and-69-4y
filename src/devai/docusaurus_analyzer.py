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
    r"(?:url|editUrl|repo|organizationName|projectName)\b[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
BROKEN_LINKS_IGNORE_PATTERN = re.compile(
    r"onBroken(?:Links|MarkdownLinks)\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"https?://[^\s\"']+",
    re.IGNORECASE,
)
DANGEROUS_HTML_PATTERN = re.compile(
    r"dangerouslySetInnerHTML|innerHTML\s*=",
    re.IGNORECASE,
)
ALGOLIA_HARDCODED_PATTERN = re.compile(
    r"algolia\s*:\s*\{[^\}]*apiKey\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
CUSTOM_FIELDS_SECRET_PATTERN = re.compile(
    r"(?:secret|token|password|apiKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
TRAILING_SLASH_FALSE_PATTERN = re.compile(
    r"trailingSlash\s*:\s*false\b",
    re.IGNORECASE,
)
NO_INDEX_FALSE_PATTERN = re.compile(
    r"noIndex\s*:\s*false\b",
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


@dataclass
class DocusaurusStats:
    """Aggregate Docusaurus analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_docusaurus_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class DocusaurusAnalyzer:
    """Audit Docusaurus configuration for documentation security and hygiene risks.

    Scans docusaurus.config.* for hardcoded secrets, ignored broken links,
    remote scripts, dangerous HTML injection, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocusaurusFinding] | None = None
        self._stats: DocusaurusStats | None = None
        self._infos: list[DocusaurusInfo] | None = None
        self._in_custom_fields = False

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

        if re.search(r"title\s*:\s*['\"]", stripped):
            info.title = stripped
        if "algolia" in stripped.lower():
            info.has_algolia = True
        if "scripts:" in stripped:
            info.has_scripts = True

        if "customFields" in stripped:
            self._in_custom_fields = True
        if self._in_custom_fields and stripped == "},":
            self._in_custom_fields = False

        in_scripts = info.has_scripts or stripped.startswith("{ src:") or "src:" in stripped
        in_custom_fields = self._in_custom_fields or "customFields" in stripped

        checks: list[tuple[re.Pattern[str], str, str, str, bool]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Docusaurus config — use env vars or CI secrets", True),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Docusaurus config — rotate and use env vars", True),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in Docusaurus config — use HTTPS endpoints", True),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high",
             "credentials embedded in url/editUrl — remove user:pass@", True),
            (BROKEN_LINKS_IGNORE_PATTERN, "broken_links_ignored", "medium",
             "onBrokenLinks set to ignore — broken links may go unnoticed", True),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium",
             "scripts array loads remote asset — self-host or pin with SRI", in_scripts),
            (DANGEROUS_HTML_PATTERN, "dangerous_html", "high",
             "dangerouslySetInnerHTML/innerHTML in config — avoid injecting untrusted HTML", True),
            (ALGOLIA_HARDCODED_PATTERN, "algolia_hardcoded", "medium",
             "Algolia apiKey hardcoded — use env vars for search credentials", True),
            (CUSTOM_FIELDS_SECRET_PATTERN, "custom_fields_secret", "high",
             "customFields contains secret-like keys — move secrets to env vars", in_custom_fields),
            (TRAILING_SLASH_FALSE_PATTERN, "trailing_slash_false", "low",
             "trailingSlash:false may cause duplicate URL issues — prefer true or undefined", True),
            (NO_INDEX_FALSE_PATTERN, "no_index_false", "low",
             "noIndex:false on staging may expose draft content to crawlers", True),
        ]

        for pattern, kind, severity, message, enabled in checks:
            if enabled and pattern.search(line):
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
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)
        return findings, info

    def analyze(self) -> list[DocusaurusFinding]:
        """Scan Docusaurus configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DocusaurusFinding] = []
        infos: list[DocusaurusInfo] = []
        paths = self.config_files()
        self._in_custom_fields = False

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
  url: 'https://example.com',
  baseUrl: '/',
  organizationName: 'org',
  projectName: 'repo',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  trailingSlash: true,

  presets: [
    [
      'classic',
      {
        docs: {
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
