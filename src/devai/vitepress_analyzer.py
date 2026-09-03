"""VitePressAnalyzer — audit .vitepress/config.* for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "config.ts",
    "config.js",
    "config.mts",
    "config.mjs",
)

VITEPRESS_MARKERS = (
    "defineConfig",
    "vitepress",
    "themeConfig",
    "title",
    "description",
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
    r"(?:editLink|repo|socialLinks)\s*:[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
HOST_ALL_INTERFACES_PATTERN = re.compile(
    r"(?:host|server\.host)\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
REMOTE_HEAD_SCRIPT_PATTERN = re.compile(
    r"head\s*:\s*\[[^\]]*src\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec|Function)\s*\(", re.IGNORECASE)
TRANSFORM_HTML_PATTERN = re.compile(
    r"transformHtml\s*:\s*\(",
    re.IGNORECASE,
)
DEFINE_SECRET_PATTERN = re.compile(
    r"(?:define\s*:\s*\{[^\}]*(?:SECRET|TOKEN|API_KEY|PASSWORD)|"
    r"(?:__)?[A-Z_]*(?:SECRET|TOKEN|API_KEY|PASSWORD)[A-Z_]*\s*:\s*['\"])",
    re.IGNORECASE,
)
IGNORE_DEAD_LINKS_PATTERN = re.compile(
    r"(?:ignoreDeadLinks|onDeadLink)\s*:\s*['\"]?(?:ignore|skip)['\"]?",
    re.IGNORECASE,
)
MARKDOWN_UNSAFE_PATTERN = re.compile(
    r"(?:html|xhtmlOut)\s*:\s*true",
    re.IGNORECASE,
)
EXTERNAL_VITE_PLUGIN_PATTERN = re.compile(
    r"plugins\s*:\s*\[[^\]]*https?://",
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
    has_theme_config: bool = False
    has_head_scripts: bool = False


@dataclass
class VitePressStats:
    """Aggregate VitePress analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_vitepress_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in VITEPRESS_MARKERS)


def _is_vitepress_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    if path.parent.name != ".vitepress":
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_vitepress_config(content)


class VitePressAnalyzer:
    """Audit VitePress configuration for documentation security and hygiene risks.

    Scans .vitepress/config.* for hardcoded secrets, exposed dev servers,
    remote head scripts, unsafe markdown settings, and transformHtml hooks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VitePressFinding] | None = None
        self._stats: VitePressStats | None = None
        self._infos: list[VitePressInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return VitePress configuration paths found in the project."""
        found: list[Path] = []
        vitepress_dir = self.root / ".vitepress"
        if vitepress_dir.is_dir():
            for name in CONFIG_NAMES:
                path = vitepress_dir / name
                if path.is_file() and _is_vitepress_config(path):
                    found.append(path)
        for path in sorted(self.root.rglob(".vitepress/*")):
            if path.is_file() and _is_vitepress_config(path) and path not in found:
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

        if stripped.startswith("title:") or stripped.startswith("title :"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\",")

        if "themeConfig" in stripped:
            info.has_theme_config = True

        if "head:" in stripped or "head :" in stripped:
            info.has_head_scripts = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in VitePress config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in VitePress config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in VitePress config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in repo/editLink URL — remove user:pass@"),
            (HOST_ALL_INTERFACES_PATTERN, "host_all_interfaces", "medium", "server host binds to all interfaces — use 127.0.0.1 for local dev"),
            (REMOTE_HEAD_SCRIPT_PATTERN, "remote_head_script", "medium", "head loads remote script — pin version and self-host assets"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in VitePress config — avoid dynamic code execution in config"),
            (TRANSFORM_HTML_PATTERN, "transform_html", "medium", "transformHtml hook can inject arbitrary HTML — review carefully"),
            (DEFINE_SECRET_PATTERN, "define_secret", "high", "define block exposes secret to client bundle — use server-side env vars"),
            (IGNORE_DEAD_LINKS_PATTERN, "ignore_dead_links", "low", "ignoreDeadLinks enabled — broken links may go unnoticed"),
            (MARKDOWN_UNSAFE_PATTERN, "markdown_unsafe", "high", "raw HTML in markdown enabled — XSS risk in rendered content"),
            (EXTERNAL_VITE_PLUGIN_PATTERN, "external_vite_plugin", "medium", "Vite plugin loaded from remote URL — pin to trusted package"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
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
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

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
  description: 'Documentation for my project',

  server: {
    host: '127.0.0.1',
  },

  themeConfig: {
    nav: [{ text: 'Home', link: '/' }],
    sidebar: [{ text: 'Guide', link: '/guide/' }],
    editLink: {
      pattern: 'https://github.com/org/repo/edit/main/docs/:path',
    },
  },

  // Self-host assets instead of loading remote scripts
  head: [],

  markdown: {
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
