"""MkDocsAnalyzer — audit mkdocs.yml for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("mkdocs.yml", "mkdocs.yaml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|analytics)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
HOOKS_PATTERN = re.compile(r"^\s*hooks\s*:", re.IGNORECASE)
EXTRA_JS_PATTERN = re.compile(r"^\s*extra_javascript\s*:", re.IGNORECASE)
EXTRA_CSS_PATTERN = re.compile(r"^\s*extra_css\s*:", re.IGNORECASE)
SNIPPETS_BASE_PATH_PATTERN = re.compile(
    r"(?:base_path|check_paths)\s*:\s*[\"']?(?:/|\.\./)",
    re.IGNORECASE,
)
GOOGLE_ANALYTICS_PATTERN = re.compile(
    r"(?:google_analytics|gtag|G-[A-Z0-9]{6,})",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^\s\"']+\.git",
    re.IGNORECASE,
)
INSECURE_CDN_PATTERN = re.compile(
    r"(?:extra_javascript|extra_css)\s*:[^\n]*http://",
    re.IGNORECASE,
)
EDIT_URI_TRAVERSAL_PATTERN = re.compile(
    r"edit_uri\s*:\s*[\"']?\.\./",
    re.IGNORECASE,
)
DISABLED_STRICT_PATTERN = re.compile(
    r"(?:strict|validation)\s*:\s*(?:false|False)",
    re.IGNORECASE,
)


@dataclass
class MkDocsFinding:
    """A security or best-practice issue in an MkDocs configuration file."""

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
    file_kind: str = ""
    site_name: str | None = None
    repo_url: str | None = None
    plugins: list[str] = field(default_factory=list)
    extra_js: list[str] = field(default_factory=list)
    extra_css: list[str] = field(default_factory=list)


@dataclass
class MkDocsStats:
    """Aggregate MkDocs analysis statistics."""

    configs: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.suffix in (".yml", ".yaml"):
        return "yaml"
    return "unknown"


def _extract_scalar(line: str) -> str | None:
    match = re.search(r":\s*[\"']?([^\"'#]+)[\"']?\s*(?:#|$)", line)
    if match:
        return match.group(1).strip()
    return None


def _extract_list_items(line: str) -> list[str]:
    items: list[str] = []
    for match in re.finditer(r"[\"']([^\"']+)[\"']", line):
        items.append(match.group(1))
    return items


class MkDocsAnalyzer:
    """Audit MkDocs configuration for documentation security and hygiene risks.

    Scans mkdocs.yml and mkdocs.yaml for hardcoded secrets, insecure HTTP assets,
    credentials in repo URLs, custom hooks, path-traversal-prone snippet settings,
    remote plugin sources, and disabled strict validation.
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
        for path in sorted(self.root.rglob("mkdocs.y*ml")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MkDocsFinding], MkDocsInfo]:
        findings: list[MkDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MkDocsInfo(path=rel)

        raw_lines = text.splitlines()
        info = MkDocsInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        in_plugins = False
        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^\s*site_name\s*:", stripped, re.IGNORECASE):
                info.site_name = _extract_scalar(stripped)
            elif re.match(r"^\s*repo_url\s*:", stripped, re.IGNORECASE):
                info.repo_url = _extract_scalar(stripped)
            elif re.match(r"^\s*plugins\s*:", stripped, re.IGNORECASE):
                in_plugins = True
                plugin_items = _extract_list_items(stripped)
                info.plugins.extend(plugin_items)
            elif in_plugins and stripped.startswith("-"):
                plugin_match = re.match(r"^\s*-\s*([a-zA-Z0-9_.-]+)", stripped)
                if plugin_match:
                    info.plugins.append(plugin_match.group(1))
            elif in_plugins and not stripped.startswith("-") and not stripped.startswith("#"):
                in_plugins = False

            if EXTRA_JS_PATTERN.search(stripped):
                info.extra_js.extend(_extract_list_items(stripped))
            if EXTRA_CSS_PATTERN.search(stripped):
                info.extra_css.extend(_extract_list_items(stripped))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret or credential in MkDocs config",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="Possible AWS access key in MkDocs config",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="credentials_in_url",
                        severity="high",
                        message="Credentials embedded in repository or plugin URL",
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
                        message="Insecure HTTP URL in MkDocs config (prefer HTTPS)",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if HOOKS_PATTERN.search(stripped):
                findings.append(
                    MkDocsFinding(
                        kind="custom_hooks",
                        severity="medium",
                        message="Custom hooks execute arbitrary Python during build",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if SNIPPETS_BASE_PATH_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="snippets_path_traversal",
                        severity="high",
                        message="Snippet base_path may allow path traversal outside docs",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if REMOTE_PLUGIN_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="remote_plugin",
                        severity="medium",
                        message="Remote git plugin source — pin to a specific commit or tag",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if INSECURE_CDN_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="insecure_cdn_asset",
                        severity="medium",
                        message="extra_javascript/extra_css loaded over insecure HTTP",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if EDIT_URI_TRAVERSAL_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="edit_uri_traversal",
                        severity="low",
                        message="edit_uri uses parent-directory traversal",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if DISABLED_STRICT_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="strict_disabled",
                        severity="low",
                        message="Strict validation disabled — broken links may go unnoticed",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if GOOGLE_ANALYTICS_PATTERN.search(line) and HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="analytics_secret",
                        severity="medium",
                        message="Analytics configuration may expose tracking identifiers",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        return findings, info

    def analyze(self) -> list[MkDocsFinding]:
        """Scan MkDocs configs and return findings."""
        if self._findings is not None:
            return self._findings

        all_findings: list[MkDocsFinding] = []
        infos: list[MkDocsInfo] = []
        stats = MkDocsStats()

        for path in self.config_files():
            findings, info = self._analyze_file(path)
            all_findings.extend(findings)
            infos.append(info)
            stats.configs += 1

        for finding in all_findings:
            stats.findings += 1
            if finding.severity == "high":
                stats.high_severity += 1
            elif finding.severity == "medium":
                stats.medium_severity += 1
            else:
                stats.low_severity += 1

        self._findings = all_findings
        self._stats = stats
        self._infos = infos
        return all_findings

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
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
        """Scaffold a hardened mkdocs.yml with secure defaults."""
        return """\
# mkdocs.yml — hardened defaults for MkDocs projects
site_name: My Project Docs
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/

theme:
  name: material

plugins:
  - search
  - minify:
      minify_html: true

# Prefer HTTPS for external assets; avoid custom hooks unless reviewed
# extra_javascript: []
# extra_css: []

strict: true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "MkDocs configs: none found"
        return (
            f"MkDocs configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "MkDocs analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            plugins = ", ".join(info.plugins[:8]) if info.plugins else "none"
            lines.append(
                f"  - {info.path}: site={info.site_name or 'unknown'}, "
                f"plugins={plugins}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
