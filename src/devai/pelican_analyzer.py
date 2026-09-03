"""PelicanAnalyzer — audit pelicanconf.py for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "pelicanconf.py",
    "publishconf.py",
)

PELICAN_MARKERS = (
    "pelican",
    "SITEURL",
    "SITENAME",
    "AUTHOR",
    "DEFAULT_LANG",
    "PATH",
    "TIMEZONE",
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
    r"(?:SITEURL|FEED_DOMAIN|GITHUB_URL|EDIT_URL)\s*=\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
SYS_PATH_PARENT_PATTERN = re.compile(
    r"sys\.path\.(?:insert|append)\s*\([^)]*(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
OS_SYSTEM_PATTERN = re.compile(
    r"\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen)\s*\(",
    re.IGNORECASE,
)
PLUGIN_PATH_PARENT_PATTERN = re.compile(
    r"PLUGIN_PATHS\s*=\s*\[[^\]]*(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
DANGEROUS_PLUGIN_PATTERN = re.compile(
    r"['\"](?:pelican-(?:shell|exec|execute)|shellcmd|rubycode)['\"]",
    re.IGNORECASE,
)
AUTOESCAPE_FALSE_PATTERN = re.compile(
    r"JINJA_ENVIRONMENT\s*=\s*\{[^\}]*['\"]autoescape['\"]\s*:\s*False",
    re.IGNORECASE,
)
RELATIVE_URLS_TRUE_PATTERN = re.compile(r"^\s*RELATIVE_URLS\s*=\s*True\b", re.IGNORECASE)
DEV_SERVER_BIND_PATTERN = re.compile(
    r"(?:DEVSERVER_HOST|HOST)\s*=\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:EXTRA_HEAD_TAGS|CUSTOM_CSS|TYPOGRIFY|GOOGLE_ANALYTICS)\s*=\s*[^\n]*https?://",
    re.IGNORECASE,
)
REMOTE_SCRIPT_LIST_PATTERN = re.compile(
    r"^\s*['\"]https?://[^\s\"']+['\"]",
    re.IGNORECASE,
)
LOAD_CONTENT_CACHE_FALSE_PATTERN = re.compile(
    r"^\s*LOAD_CONTENT_CACHE\s*=\s*False\b",
    re.IGNORECASE,
)
DELETE_OUTPUT_DIRECTORY_FALSE_PATTERN = re.compile(
    r"^\s*DELETE_OUTPUT_DIRECTORY\s*=\s*False\b",
    re.IGNORECASE,
)
GITHUB_TOKEN_PATTERN = re.compile(
    r"(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_API_TOKEN)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)


@dataclass
class PelicanFinding:
    """A security or best-practice issue in a Pelican configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PelicanInfo:
    """Parsed metadata about a Pelican configuration file."""

    path: str
    lines: int = 0
    site_name: str | None = None
    site_url: str | None = None
    plugins: list[str] = field(default_factory=list)
    has_publish_config: bool = False


@dataclass
class PelicanStats:
    """Aggregate Pelican analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_pelican_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in PELICAN_MARKERS)


def _is_pelican_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_pelican_config(content)


class PelicanAnalyzer:
    """Audit Pelican configuration for documentation security and hygiene risks.

    Scans pelicanconf.py and publishconf.py for hardcoded secrets, unsafe sys.path
    manipulation, eval/exec usage, disabled Jinja autoescape, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PelicanFinding] | None = None
        self._stats: PelicanStats | None = None
        self._infos: list[PelicanInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Pelican configuration paths found in the project."""
        found: list[Path] = []
        preferred_dirs = ("content", "docs", "doc", "blog", "site")
        for dirname in preferred_dirs:
            for name in CONFIG_NAMES:
                path = self.root / dirname / name
                if path.is_file() and _is_pelican_config(path) and path not in found:
                    found.append(path)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_pelican_config(path) and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("*.py")):
            if path.name in CONFIG_NAMES and _is_pelican_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PelicanFinding],
        info: PelicanInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if stripped.startswith("SITENAME ="):
            info.site_name = stripped.split("=", 1)[1].strip().strip("'\"")
        elif stripped.startswith("SITEURL ="):
            info.site_url = stripped.split("=", 1)[1].strip().strip("'\"")
        elif "PLUGINS" in stripped and ("[" in stripped or stripped.endswith("=")):
            for match in re.finditer(r"['\"]([^'\"]+)['\"]", stripped):
                plugin = match.group(1)
                if plugin and not plugin.startswith("http"):
                    info.plugins.append(plugin)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (
                HARDCODED_SECRET_PATTERN,
                "hardcoded_secret",
                "high",
                "hardcoded secret in Pelican config — use env vars or CI secrets",
            ),
            (
                AWS_ACCESS_KEY_PATTERN,
                "aws_access_key",
                "high",
                "AWS access key in Pelican config — rotate and use env vars",
            ),
            (
                GITHUB_TOKEN_PATTERN,
                "github_token",
                "high",
                "GitHub token in Pelican config — use env vars or CI secrets",
            ),
            (
                INSECURE_HTTP_PATTERN,
                "insecure_http",
                "medium",
                "insecure HTTP URL in Pelican config — use HTTPS endpoints",
            ),
            (
                CREDENTIAL_IN_URL_PATTERN,
                "credential_in_url",
                "high",
                "credentials embedded in SITEURL/FEED_DOMAIN — remove user:pass@",
            ),
            (
                SYS_PATH_PARENT_PATTERN,
                "unsafe_sys_path",
                "high",
                "sys.path includes parent or system directory — restrict to project paths",
            ),
            (
                EVAL_EXEC_PATTERN,
                "eval_exec",
                "high",
                "eval/exec in Pelican config — avoid dynamic code execution in config",
            ),
            (
                OS_SYSTEM_PATTERN,
                "shell_execution",
                "high",
                "shell/subprocess call in Pelican config — avoid command execution in config",
            ),
            (
                PLUGIN_PATH_PARENT_PATTERN,
                "unsafe_plugin_path",
                "medium",
                "PLUGIN_PATHS includes parent or system directory — restrict to project paths",
            ),
            (
                DANGEROUS_PLUGIN_PATTERN,
                "dangerous_plugin",
                "high",
                "dangerous Pelican plugin — avoid shell/exec plugins in production",
            ),
            (
                AUTOESCAPE_FALSE_PATTERN,
                "autoescape_disabled",
                "high",
                "JINJA_ENVIRONMENT autoescape disabled — XSS risk in generated pages",
            ),
            (
                RELATIVE_URLS_TRUE_PATTERN,
                "relative_urls",
                "low",
                "RELATIVE_URLS = True can break canonical URLs and feeds — use absolute URLs in production",
            ),
            (
                DEV_SERVER_BIND_PATTERN,
                "bind_all_interfaces",
                "medium",
                "dev server binds to all interfaces — use 127.0.0.1 for local dev",
            ),
            (
                REMOTE_SCRIPT_PATTERN,
                "remote_asset",
                "medium",
                "remote script or analytics URL in Pelican config — pin version and self-host assets",
            ),
            (
                REMOTE_SCRIPT_LIST_PATTERN,
                "remote_asset",
                "medium",
                "remote script or analytics URL in Pelican config — pin version and self-host assets",
            ),
            (
                LOAD_CONTENT_CACHE_FALSE_PATTERN,
                "content_cache_disabled",
                "low",
                "LOAD_CONTENT_CACHE = False slows builds and may mask stale content issues",
            ),
            (
                DELETE_OUTPUT_DIRECTORY_FALSE_PATTERN,
                "output_cleanup_disabled",
                "low",
                "DELETE_OUTPUT_DIRECTORY = False may leave stale files in output — enable cleanup",
            ),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    PelicanFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[PelicanFinding], PelicanInfo]:
        findings: list[PelicanFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PelicanInfo(path=rel)

        info = PelicanInfo(
            path=rel,
            lines=len(raw_lines),
            has_publish_config=path.name == "publishconf.py",
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PelicanFinding]:
        """Scan Pelican configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PelicanFinding] = []
        infos: list[PelicanInfo] = []
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
        self._stats = PelicanStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PelicanStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PelicanInfo]:
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
        """Scaffold a hardened Pelican configuration template."""
        return """\
# Generated by DevAI PelicanAnalyzer
AUTHOR = "Your Name"
SITENAME = "My Project Blog"
SITEURL = "https://example.com"

PATH = "content"
TIMEZONE = "UTC"
DEFAULT_LANG = "en"

PAGE_PATHS = ["pages"]
PAGE_EXCLUDES = []
STATIC_PATHS = ["images"]

# Use env vars for analytics and third-party keys
# GOOGLE_ANALYTICS = os.environ.get("GOOGLE_ANALYTICS", "")

RELATIVE_URLS = False
LOAD_CONTENT_CACHE = True
DELETE_OUTPUT_DIRECTORY = True

JINJA_ENVIRONMENT = {"autoescape": True}

PLUGINS = [
    "sitemap",
    "feed_summary",
]

# Self-host assets instead of loading remote scripts/stylesheets
EXTRA_HEAD_TAGS = []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pelican configs: none found"
        return (
            f"Pelican configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pelican analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
