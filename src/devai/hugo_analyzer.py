"""HugoAnalyzer — audit Hugo hugo.toml/config.* for documentation security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "hugo.toml",
    "config.toml",
    "config.yaml",
    "config.yml",
)

HUGO_MARKER_PATTERN = re.compile(
    r"(?:^baseURL\s*=|^\[params\]|^theme\s*=|^title\s*=|^\[markup\]|^enableGitInfo\s*=)",
    re.IGNORECASE | re.MULTILINE,
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
    r"(?:baseURL|repo|editURL|url)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
SERVER_BIND_ALL_PATTERN = re.compile(
    r"(?:bindAddr|bind)\s*[=:]\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
GOLDMARK_UNSAFE_PATTERN = re.compile(
    r"(?:unsafe|Unsafe)\s*=\s*true\b",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:customJS|scripts|js)\s*[=:]\s*[^\n]*https?://",
    re.IGNORECASE,
)
PUBLISH_DIR_OUTSIDE_PATTERN = re.compile(
    r"(?:publishDir|destination)\s*[=:]\s*['\"]?(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
MODULE_CREDENTIALS_PATTERN = re.compile(
    r"(?:path|module|imports)\b[^\n]*(?:https?://)[^:\s/]+:[^@\s/]+@|"
    r"(?:https?://)[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
IGNORE_ERRORS_PATTERN = re.compile(
    r"(?:ignoreErrors|ignoreLogs|ignoreFiles)\s*=\s*true\b",
    re.IGNORECASE,
)
DISABLED_ROBOTS_PATTERN = re.compile(
    r"(?:enableRobotsTXT)\s*=\s*false\b",
    re.IGNORECASE,
)


@dataclass
class HugoFinding:
    """A security or best-practice issue in a Hugo configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HugoInfo:
    """Parsed metadata about a Hugo configuration file."""

    path: str
    lines: int = 0
    base_url: str | None = None
    theme: str | None = None
    has_modules: bool = False


@dataclass
class HugoStats:
    """Aggregate Hugo analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_hugo_file(path: Path) -> bool:
    if path.name in CONFIG_NAMES:
        if path.name == "config.toml" or path.name == "hugo.toml":
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if HUGO_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class HugoAnalyzer:
    """Audit Hugo configuration for documentation security and hygiene risks.

    Scans hugo.toml and config.* for hardcoded secrets, exposed dev servers,
    unsafe Goldmark settings, remote scripts, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HugoFinding] | None = None
        self._stats: HugoStats | None = None
        self._infos: list[HugoInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Hugo configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_hugo_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HugoFinding],
        info: HugoInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if stripped.lower().startswith("baseurl"):
            info.base_url = stripped.split("=", 1)[-1].strip().strip("'\"")

        if stripped.lower().startswith("theme"):
            info.theme = stripped.split("=", 1)[-1].strip().strip("'\"")

        if "[module]" in stripped.lower() or stripped.lower().startswith("imports"):
            info.has_modules = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Hugo config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Hugo config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in Hugo config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high",
             "credentials embedded in baseURL/repo URL — remove user:pass@"),
            (SERVER_BIND_ALL_PATTERN, "server_bind_all", "medium",
             "server binds to all interfaces — use 127.0.0.1 for local dev"),
            (GOLDMARK_UNSAFE_PATTERN, "goldmark_unsafe", "high",
             "Goldmark unsafe=true allows raw HTML — restrict to trusted content"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium",
             "remote script in Hugo config — self-host or pin with SRI"),
            (PUBLISH_DIR_OUTSIDE_PATTERN, "publish_dir_outside", "high",
             "publishDir points outside project — restrict to trusted directories"),
            (MODULE_CREDENTIALS_PATTERN, "module_credentials", "high",
             "Hugo module import URL contains credentials — use token env vars"),
            (IGNORE_ERRORS_PATTERN, "ignore_errors", "low",
             "ignoreErrors/ignoreLogs enabled — build issues may go unnoticed"),
            (DISABLED_ROBOTS_PATTERN, "robots_disabled", "low",
             "enableRobotsTXT=false may affect search indexing controls"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    HugoFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[HugoFinding], HugoInfo]:
        findings: list[HugoFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HugoInfo(path=rel)

        info = HugoInfo(path=rel, lines=len(raw_lines))
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)
        return findings, info

    def analyze(self) -> list[HugoFinding]:
        """Scan Hugo configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HugoFinding] = []
        infos: list[HugoInfo] = []
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
        self._stats = HugoStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HugoStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HugoInfo]:
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
        """Scaffold a hardened Hugo configuration template."""
        return """\
# Generated by DevAI HugoAnalyzer
baseURL = "https://example.com/"
languageCode = "en-us"
title = "My Project Docs"
theme = "docsy"

enableRobotsTXT = true
enableGitInfo = false

[markup.goldmark.renderer]
  unsafe = false

[server]
  bind = "127.0.0.1"
  port = 1313

publishDir = "public"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Hugo configs: none found"
        return (
            f"Hugo configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Hugo analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
