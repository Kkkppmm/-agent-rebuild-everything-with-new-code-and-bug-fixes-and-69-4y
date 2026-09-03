"""DocsifyAnalyzer — audit index.html and docsify init scripts for documentation security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("index.html", "index.htm")
DOCSIFY_MARKERS = (
    "docsify",
    "$docsify",
    "window.$docsify",
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
    r"(?:repo|homepage|basePath|loadSidebar|loadNavbar)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
EXECUTE_SCRIPT_TRUE_PATTERN = re.compile(
    r"executeScript\s*:\s*true\b",
    re.IGNORECASE,
)
REQUEST_HEADERS_PATTERN = re.compile(
    r"requestHeaders\s*:\s*\{",
    re.IGNORECASE,
)
AUTH_HEADER_VALUE_PATTERN = re.compile(
    r"['\"]?(?:authorization|x-api-key|x-auth-token)['\"]?\s*:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
REMOTE_SIDEBAR_PATTERN = re.compile(
    r"(?:loadSidebar|loadNavbar|loadFooter)\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
BASE_PATH_PARENT_PATTERN = re.compile(
    r"basePath\s*:\s*['\"]?(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
REMOTE_HOMEPAGE_PATTERN = re.compile(
    r"homepage\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
GA_INLINE_PATTERN = re.compile(
    r"(?:ga|gtag)\s*:\s*['\"][A-Z]{2}-[A-Z0-9-]+['\"]",
    re.IGNORECASE,
)
CDN_SCRIPT_PATTERN = re.compile(
    r"<script[^>]+src=['\"](?:https?:)?//(?:unpkg|cdn\.jsdelivr|cdnjs)\.",
    re.IGNORECASE,
)
SCRIPT_WITHOUT_INTEGRITY_PATTERN = re.compile(
    r"<script(?![^>]*\bintegrity=)[^>]+src=['\"]https?://",
    re.IGNORECASE,
)
MERGE_HEADERS_FALSE_PATTERN = re.compile(
    r"mergeHeaders\s*:\s*false\b",
    re.IGNORECASE,
)
NOT_FOUND_DISABLED_PATTERN = re.compile(
    r"notFoundPage\s*:\s*false\b",
    re.IGNORECASE,
)


@dataclass
class DocsifyFinding:
    """A security or best-practice issue in a Docsify configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DocsifyInfo:
    """Parsed metadata about a Docsify configuration file."""

    path: str
    lines: int = 0
    name: str | None = None
    has_plugins: bool = False
    has_request_headers: bool = False
    uses_cdn: bool = False


@dataclass
class DocsifyStats:
    """Aggregate Docsify analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_docsify_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker in lowered for marker in DOCSIFY_MARKERS)


def _is_docsify_file(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_docsify_config(content)


class DocsifyAnalyzer:
    """Audit Docsify index.html and init scripts for documentation security risks.

    Scans Docsify entry HTML for hardcoded secrets, remote script includes without
    integrity, executeScript, unsafe requestHeaders, and insecure base paths.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocsifyFinding] | None = None
        self._stats: DocsifyStats | None = None
        self._infos: list[DocsifyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Docsify index.html paths found in the project."""
        found: list[Path] = []
        preferred_dirs = ("docs", "doc", "documentation", "public", "www")
        for dirname in preferred_dirs:
            for name in CONFIG_NAMES:
                path = self.root / dirname / name
                if path.is_file() and _is_docsify_file(path) and path not in found:
                    found.append(path)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_docsify_file(path) and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_docsify_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DocsifyFinding],
        info: DocsifyInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped:
            return section

        if stripped.endswith("{") and "requestHeaders" in stripped:
            section = "request_headers"
        elif stripped in ("},", "}") and section == "request_headers":
            section = ""
        elif "plugins" in stripped and ("[" in stripped or stripped.endswith(":")):
            section = "plugins"
        elif stripped == "]" and section == "plugins":
            section = ""

        if stripped.startswith("name:") or "name:" in stripped:
            match = re.search(r"name\s*:\s*['\"]([^'\"]+)['\"]", stripped)
            if match:
                info.name = match.group(1)

        if "plugins" in stripped and ("[" in stripped or ":" in stripped):
            info.has_plugins = True

        if REQUEST_HEADERS_PATTERN.search(stripped) and section != "request_headers":
            info.has_request_headers = True

        if CDN_SCRIPT_PATTERN.search(stripped):
            info.uses_cdn = True

        if section == "plugins" and re.search(r"https?://", stripped):
            findings.append(
                DocsifyFinding(
                    kind="remote_plugin",
                    severity="high",
                    message="plugins array references remote URL — only load trusted local plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Docsify config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Docsify config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Docsify config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in Docsify URL setting — remove user:pass@"),
            (EXECUTE_SCRIPT_TRUE_PATTERN, "execute_script", "high", "executeScript: true runs inline scripts from markdown — disable unless required"),
            (AUTH_HEADER_VALUE_PATTERN, "auth_header", "high", "authorization header hardcoded in requestHeaders — use server-side proxy"),
            (REMOTE_SIDEBAR_PATTERN, "remote_sidebar", "high", "loadSidebar/loadNavbar loads remote content — host navigation locally"),
            (BASE_PATH_PARENT_PATTERN, "unsafe_base_path", "high", "basePath includes parent or system directory — restrict to project paths"),
            (REMOTE_HOMEPAGE_PATTERN, "remote_homepage", "medium", "homepage loads remote markdown — host content locally"),
            (SCRIPT_WITHOUT_INTEGRITY_PATTERN, "missing_integrity", "medium", "external script without integrity attribute — add SRI or self-host assets"),
            (CDN_SCRIPT_PATTERN, "cdn_script", "medium", "Docsify loaded from public CDN — pin version and self-host for supply-chain safety"),
            (GA_INLINE_PATTERN, "inline_analytics", "low", "inline analytics ID in Docsify config — load analytics via tag manager with consent"),
            (MERGE_HEADERS_FALSE_PATTERN, "merge_headers_false", "low", "mergeHeaders: false may break heading anchors — prefer default behavior"),
            (NOT_FOUND_DISABLED_PATTERN, "not_found_disabled", "low", "notFoundPage: false hides broken-link feedback — enable custom 404 page"),
        ]

        if REQUEST_HEADERS_PATTERN.search(stripped) and section == "request_headers":
            findings.append(
                DocsifyFinding(
                    kind="request_headers",
                    severity="medium",
                    message="requestHeaders configured — ensure tokens are not hardcoded in client-side config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    DocsifyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[DocsifyFinding], DocsifyInfo]:
        findings: list[DocsifyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DocsifyInfo(path=rel)

        info = DocsifyInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def analyze(self) -> list[DocsifyFinding]:
        """Scan Docsify configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DocsifyFinding] = []
        infos: list[DocsifyInfo] = []
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
        self._stats = DocsifyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DocsifyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DocsifyInfo]:
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
        """Scaffold a hardened Docsify index.html template."""
        return """\
<!-- Generated by DevAI DocsifyAnalyzer -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>My Project Docs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link rel="stylesheet" href="/docsify/lib/themes/vue.css" />
</head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'My Project',
      repo: 'https://github.com/org/repo',
      homepage: 'README.md',
      loadSidebar: true,
      subMaxLevel: 2,
      auto2top: true,
      mergeHeaders: true,
      notFoundPage: true,
      executeScript: false,
      requestHeaders: {},
      plugins: []
    };
  </script>
  <script src="/docsify/lib/docsify.min.js"></script>
  <script src="/docsify/lib/plugins/search.min.js"></script>
</body>
</html>
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Docsify configs: none found"
        return (
            f"Docsify configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Docsify analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
