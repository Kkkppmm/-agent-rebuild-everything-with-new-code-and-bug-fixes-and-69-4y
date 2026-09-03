"""VitePressAnalyzer — audit .vitepress/config.* for documentation security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = ".vitepress"
CONFIG_NAMES = ("config.ts", "config.js", "config.mjs", "config.cjs")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|algolia[A-Z][a-zA-Z]*)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"https?://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
SERVER_HOST_ALL_PATTERN = re.compile(
    r"(?:host|hostname)\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
FS_ALLOW_PARENT_PATTERN = re.compile(
    r"(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
REMOTE_HEAD_SCRIPT_PATTERN = re.compile(
    r"(?:head|scripts)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
BROKEN_LINKS_IGNORE_PATTERN = re.compile(
    r"(?:onDeadLink|onBrokenLink)\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
MARKDOWN_UNSAFE_PATTERN = re.compile(
    r"(?:html|xss|dangerouslySetInnerHTML)\s*:\s*true\b",
    re.IGNORECASE,
)
ALGOLIA_ADMIN_KEY_PATTERN = re.compile(
    r"algolia\s*:\s*\{[^\}]*apiKey\s*:\s*['\"][a-f0-9]{32,}['\"]",
    re.IGNORECASE,
)


@dataclass
class VitePressFinding:
    """A security or best-practice issue in a VitePress configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class VitePressInfo:
    """Parsed metadata about a VitePress configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    has_search: bool = False
    has_head_scripts: bool = False


@dataclass
class VitePressStats:
    """Aggregate VitePress analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vitepress_file(path: Path) -> bool:
    return path.parent.name == CONFIG_DIR and path.name in CONFIG_NAMES


class VitePressAnalyzer:
    """Audit VitePress configuration for documentation security and hygiene risks.

    Scans .vitepress/config.* for hardcoded secrets, exposed dev servers,
    permissive Vite fs.allow, remote head scripts, and insecure URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitePressFinding] | None = None
        self._stats: VitePressStats | None = None
        self._infos: list[VitePressInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return VitePress configuration paths found in the project."""
        found: list[Path] = []
        vitepress_dir = self.root / CONFIG_DIR
        if vitepress_dir.is_dir():
            for name in CONFIG_NAMES:
                path = vitepress_dir / name
                if path.is_file():
                    found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_vitepress_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[VitePressFinding],
        info: VitePressInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if re.search(r"title\s*:\s*['\"]", stripped):
            info.title = stripped
        if "search:" in stripped or "provider:" in stripped:
            info.has_search = True
        if "head:" in stripped or "scripts:" in stripped:
            info.has_head_scripts = True

        in_fs_allow = "allow:" in stripped or "../" in stripped or "/tmp/" in stripped

        checks: list[tuple[re.Pattern[str], str, str, str, bool]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in VitePress config — use env vars or CI secrets", True),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in VitePress config — rotate and use env vars", True),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in VitePress config — use HTTPS endpoints", True),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high",
             "credentials embedded in repo/edit links — remove user:pass@", True),
            (SERVER_HOST_ALL_PATTERN, "server_host_all", "medium",
             "dev server binds to all interfaces — use 127.0.0.1 for local dev", True),
            (FS_ALLOW_PARENT_PATTERN, "fs_allow_parent", "high",
             "Vite fs.allow includes parent/system paths — restrict to project root", in_fs_allow),
            (REMOTE_HEAD_SCRIPT_PATTERN, "remote_head_script", "medium",
             "head/scripts loads remote asset — self-host or pin with SRI", True),
            (BROKEN_LINKS_IGNORE_PATTERN, "broken_links_ignored", "low",
             "onDeadLink/onBrokenLink set to ignore — broken links may go unnoticed", True),
            (MARKDOWN_UNSAFE_PATTERN, "markdown_unsafe", "high",
             "unsafe HTML rendering enabled — restrict to trusted markdown", True),
            (ALGOLIA_ADMIN_KEY_PATTERN, "algolia_hardcoded_key", "medium",
             "Algolia apiKey hardcoded — use env vars for search credentials", True),
        ]

        for pattern, kind, severity, message, enabled in checks:
            if enabled and pattern.search(line):
                findings.append(
                    VitePressFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[VitePressFinding], VitePressInfo]:
        findings: list[VitePressFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, VitePressInfo(path=rel)

        info = VitePressInfo(path=rel, lines=len(raw_lines))
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)
        return findings, info

    def analyze(self) -> list[VitePressFinding]:
        """Scan VitePress configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VitePressFinding] = []
        infos: list[VitePressInfo] = []
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
        self._stats = VitePressStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VitePressStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VitePressInfo]:
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
        """Scaffold a hardened VitePress configuration template."""
        return """\
// Generated by DevAI VitePressAnalyzer
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'My Project Docs',
  description: 'Project documentation',
  base: '/docs/',

  themeConfig: {
    editLink: {
      pattern: 'https://github.com/org/repo/edit/main/docs/:path',
    },
    search: {
      provider: 'local',
    },
  },

  vite: {
    server: {
      host: '127.0.0.1',
      fs: {
        allow: ['.'],
      },
    },
  },

  markdown: {
    // Keep HTML disabled unless content is fully trusted
    html: false,
  },
})
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "VitePress configs: none found"
        return (
            f"VitePress configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "VitePress analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
