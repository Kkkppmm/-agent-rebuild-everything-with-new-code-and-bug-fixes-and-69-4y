"""HugoAnalyzer — audit Hugo config files for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "hugo.toml",
    "config.toml",
    "config.yaml",
    "config.yml",
    "config.json",
)

HUGO_MARKERS = (
    "baseurl",
    "baseURL",
    "languagecode",
    "languageCode",
    "theme",
    "themesdir",
    "themesDir",
    "module",
    "markup",
    "goldmark",
    "params",
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
    r"(?:baseURL|baseurl|canonifyURLs|uglyURLs)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
GOLDMARK_UNSAFE_PATTERN = re.compile(
    r"(?:unsafe|allowActionJavaScript)\s*=\s*true",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:bind|serverBind)\s*[=:]\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:customHead|customFooter|customJS|head|footer)\s*[=:].*https?://",
    re.IGNORECASE,
)
INSECURE_MODULE_PATTERN = re.compile(
    r"(?:imports|path)\s*=\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
DISABLE_ROBOTS_PATTERN = re.compile(
    r"(?:enableRobotsTXT|enableGitInfo)\s*=\s*false",
    re.IGNORECASE,
)
BUILD_DRAFTS_PATTERN = re.compile(
    r"(?:buildDrafts|buildFuture|buildExpired)\s*=\s*true",
    re.IGNORECASE,
)
EXECUTE_AS_TEMPLATE_PATTERN = re.compile(
    r"(?:executeAsTemplate|renderShortcodes)\s*=\s*true",
    re.IGNORECASE,
)
DISABLE_LIVE_RELOAD_PATTERN = re.compile(
    r"disableLiveReload\s*=\s*false",
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
    title: str | None = None
    base_url: str | None = None
    has_module: bool = False
    has_markup: bool = False
    themes: list[str] = field(default_factory=list)


@dataclass
class HugoStats:
    """Aggregate Hugo analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_hugo_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in HUGO_MARKERS)


def _is_hugo_file(path: Path) -> bool:
    if path.name not in CONFIG_NAMES and path.name != "hugo.toml":
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_hugo_config(content)


class HugoAnalyzer:
    """Audit Hugo configuration for documentation security and hygiene risks.

    Scans hugo.toml/config.* for hardcoded secrets, unsafe Goldmark settings,
    exposed dev servers, insecure module imports, and remote script injection.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HugoFinding] | None = None
        self._stats: HugoStats | None = None
        self._infos: list[HugoInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Hugo configuration paths found in the project."""
        found: list[Path] = []
        preferred = (
            self.root / "hugo.toml",
            self.root / "config.toml",
            self.root / "config.yaml",
            self.root / "config.yml",
            self.root / "config.json",
            self.root / "config" / "config.toml",
            self.root / "config" / "_default" / "config.toml",
        )
        for path in preferred:
            if path.is_file() and _is_hugo_file(path):
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
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]").lower()
        elif stripped.endswith(":") and not stripped.startswith("-"):
            section = stripped[:-1].strip().lower()

        if stripped.lower().startswith("title"):
            info.title = stripped.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")

        if stripped.lower().startswith("baseurl"):
            info.base_url = stripped.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")

        if section in ("module", "modules"):
            info.has_module = True
        if section in ("markup", "goldmark"):
            info.has_markup = True
        if section == "theme" and "=" in stripped:
            theme = stripped.split("=", 1)[-1].strip().strip("'\"")
            if theme:
                info.themes.append(theme)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Hugo config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Hugo config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Hugo config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in baseURL — remove user:pass@"),
            (GOLDMARK_UNSAFE_PATTERN, "goldmark_unsafe", "high", "Goldmark unsafe mode allows raw HTML/JS — keep unsafe disabled"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium", "Hugo server binds to all interfaces — restrict to localhost in dev"),
            (REMOTE_SCRIPT_PATTERN, "remote_script", "medium", "custom head/footer loads remote script — self-host assets"),
            (INSECURE_MODULE_PATTERN, "insecure_module", "high", "Hugo module imported over HTTP — use HTTPS or local paths"),
            (BUILD_DRAFTS_PATTERN, "build_drafts", "medium", "buildDrafts/buildFuture enabled — drafts may leak to production"),
            (EXECUTE_AS_TEMPLATE_PATTERN, "execute_as_template", "high", "executeAsTemplate allows arbitrary template execution — disable in production"),
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

        if DISABLE_ROBOTS_PATTERN.search(line):
            findings.append(
                HugoFinding(
                    kind="disabled_robots",
                    severity="low",
                    message="enableRobotsTXT disabled — search engines may index unintended pages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[HugoFinding], HugoInfo]:
        findings: list[HugoFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HugoInfo(path=rel)

        info = HugoInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

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
        """Scaffold a hardened hugo.toml template."""
        return """\
# Generated by DevAI HugoAnalyzer
baseURL = "https://example.com/"
languageCode = "en-us"
title = "My Project"
theme = "docsy"

enableRobotsTXT = true
enableGitInfo = false

[markup.goldmark.renderer]
  unsafe = false

[server]
  bind = "127.0.0.1"

[params]
  description = "Project documentation"
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
