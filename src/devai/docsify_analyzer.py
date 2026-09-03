"""DocsifyAnalyzer — audit index.html and docsify init scripts for security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAMES = (
    "index.html",
    "docsify-init.js",
    "docsify.config.js",
)

DOCSIFY_MARKERS = (
    "$docsify",
    "window.$docsify",
    "docsify",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:src|href)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)[^\"']+['\"]",
    re.IGNORECASE,
)
PROTOCOL_RELATIVE_CDN_PATTERN = re.compile(
    r"(?:src|href)\s*=\s*['\"]//[^\"']+['\"]",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:repo|basePath|homepage|alias)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
REQUEST_HEADERS_AUTH_PATTERN = re.compile(
    r"requestHeaders\s*:\s*\{[^\}]*(?:Authorization|Bearer|X-Api-Key|token)",
    re.IGNORECASE,
)
AUTH_HEADER_VALUE_PATTERN = re.compile(
    r"(?:Authorization|Bearer|X-Api-Key)\s*:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
REMOTE_ALIAS_PATTERN = re.compile(
    r"alias\s*:\s*\{[^\}]*['\"]https?://",
    re.IGNORECASE,
)
ALIAS_REMOTE_URL_PATTERN = re.compile(
    r"^\s*['\"][^'\"]+['\"]\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec|Function)\s*\(", re.IGNORECASE)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:plugins|script)\s*:\s*\[[^\]]*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_PLUGIN_LINE_PATTERN = re.compile(
    r"^\s*['\"]https?://[^'\"]+['\"]",
    re.IGNORECASE,
)
REMOTE_PLUGIN_SRC_PATTERN = re.compile(
    r"<script[^>]+src\s*=\s*['\"]https?://[^\"']+/docsify[^\"']*['\"][^>]*>",
    re.IGNORECASE,
)
NO_INTEGRITY_CDN_PATTERN = re.compile(
    r"<script[^>]+src\s*=\s*['\"](?:https?:)?//[^\"']+['\"](?![^>]*integrity=)[^>]*>",
    re.IGNORECASE,
)
EXEC_SCRIPT_PLUGIN_PATTERN = re.compile(
    r"executeScript\s*:\s*true",
    re.IGNORECASE,
)
MERGE_HEADERS_PATTERN = re.compile(
    r"mergeHeaders\s*:\s*true",
    re.IGNORECASE,
)
EXTERNAL_LINK_UNSAFE_PATTERN = re.compile(
    r"externalLinkTarget\s*:\s*['\"]_blank['\"]",
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
    return any(marker.lower() in lowered for marker in DOCSIFY_MARKERS)


def _is_docsify_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES and not path.name.endswith("docsify.config.js"):
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_docsify_config(content)


class DocsifyAnalyzer:
    """Audit Docsify configuration for documentation security and hygiene risks.

    Scans index.html and docsify init scripts for hardcoded secrets, remote CDN
    scripts without integrity, auth headers in client config, and unsafe plugins.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DocsifyFinding] | None = None
        self._stats: DocsifyStats | None = None
        self._infos: list[DocsifyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Docsify configuration paths found in the project."""
        found: list[Path] = []
        candidates: list[Path] = []

        for name in CONFIG_NAMES:
            candidates.append(self.root / name)
            candidates.append(self.root / "docs" / name)
            candidates.append(self.root / "public" / name)

        for path in candidates:
            if path.is_file() and _is_docsify_config(path):
                found.append(path)

        for path in sorted(self.root.rglob("index.html")):
            if path.is_file() and _is_docsify_config(path) and path not in found:
                found.append(path)

        for path in sorted(self.root.rglob("docsify*.js")):
            if path.is_file() and _is_docsify_config(path) and path not in found:
                found.append(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DocsifyFinding],
        info: DocsifyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if stripped.startswith("name:") or stripped.startswith("name :"):
            info.name = stripped.split(":", 1)[1].strip().strip("'\",")

        if "plugins" in stripped:
            info.has_plugins = True

        if "requestHeaders" in stripped:
            info.has_request_headers = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Docsify config — use server-side auth or env vars"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Docsify config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP asset URL in Docsify config — use HTTPS endpoints"),
            (PROTOCOL_RELATIVE_CDN_PATTERN, "protocol_relative_cdn", "medium", "protocol-relative CDN URL — prefer HTTPS with pinned version and SRI"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in repo/basePath URL — remove user:pass@"),
            (REQUEST_HEADERS_AUTH_PATTERN, "request_headers_auth", "high", "auth token in requestHeaders — never expose credentials in client config"),
            (AUTH_HEADER_VALUE_PATTERN, "request_headers_auth", "high", "auth token in requestHeaders — never expose credentials in client config"),
            (REMOTE_ALIAS_PATTERN, "remote_alias", "medium", "alias loads content from remote URL — verify trust and use HTTPS"),
            (ALIAS_REMOTE_URL_PATTERN, "remote_alias", "medium", "alias loads content from remote URL — verify trust and use HTTPS"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Docsify config — avoid dynamic code execution"),
            (REMOTE_PLUGIN_PATTERN, "remote_plugin", "medium", "Docsify plugin loaded from remote URL — pin version and self-host assets"),
            (REMOTE_PLUGIN_LINE_PATTERN, "remote_plugin", "medium", "Docsify plugin loaded from remote URL — pin version and self-host assets"),
            (REMOTE_PLUGIN_SRC_PATTERN, "remote_plugin_src", "medium", "Docsify core loaded from remote CDN — pin version and add integrity attribute"),
            (NO_INTEGRITY_CDN_PATTERN, "no_integrity_cdn", "low", "CDN script without integrity attribute — add SRI hash for supply-chain safety"),
            (EXEC_SCRIPT_PLUGIN_PATTERN, "execute_script", "high", "executeScript enabled — arbitrary script execution in markdown"),
            (MERGE_HEADERS_PATTERN, "merge_headers", "medium", "mergeHeaders enabled — HTML headers can inject unsafe content"),
        ]

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

    def _analyze_file(self, path: Path) -> tuple[list[DocsifyFinding], DocsifyInfo]:
        findings: list[DocsifyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DocsifyInfo(path=rel)

        info = DocsifyInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        content = "\n".join(raw_lines)
        if "externalLinkTarget" in content and "externalLinkRel" not in content:
            for finding in list(findings):
                if finding.kind == "external_link_blank":
                    break
            else:
                for lineno, raw in enumerate(raw_lines, start=1):
                    if EXTERNAL_LINK_UNSAFE_PATTERN.search(raw):
                        findings.append(
                            DocsifyFinding(
                                kind="external_link_blank",
                                severity="low",
                                message=(
                                    "externalLinkTarget _blank without rel=noopener — "
                                    "add externalLinkRel for tabnabbing protection"
                                ),
                                path=rel,
                                lineno=lineno,
                                line=raw.rstrip(),
                            )
                        )
                        break
        else:
            findings = [f for f in findings if f.kind != "external_link_blank"]

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
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/docsify@4/themes/vue.css" />
</head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'My Project Docs',
      repo: 'https://github.com/org/repo',
      loadSidebar: true,
      externalLinkTarget: '_blank',
      externalLinkRel: 'noopener noreferrer',
      executeScript: false,
      mergeHeaders: false,
    }
  </script>
  <script
    src="https://cdn.jsdelivr.net/npm/docsify@4/lib/docsify.min.js"
    integrity="sha384-REPLACE_WITH_SRI_HASH"
    crossorigin="anonymous"
  ></script>
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
