"""EleventyAnalyzer — audit .eleventy.js and eleventy.config.* for security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAMES = (
    ".eleventy.js",
    ".eleventy.cjs",
    ".eleventy.mjs",
    "eleventy.config.js",
    "eleventy.config.cjs",
    "eleventy.config.mjs",
)

ELEVENTY_MARKERS = (
    "eleventyConfig",
    "eleventy",
    "addPassthroughCopy",
    "setLiquidOptions",
    "setServerOptions",
    "markdownTemplateEngine",
    "htmlTemplateEngine",
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
    r"(?:url|pathPrefix|permalink)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
SHOW_ALL_HOSTS_PATTERN = re.compile(
    r"showAllHosts\s*:\s*true",
    re.IGNORECASE,
)
BIND_ALL_INTERFACES_PATTERN = re.compile(
    r"(?:host|hostname|listen)\s*:\s*['\"]?(?:0\.0\.0\.0|::)['\"]?",
    re.IGNORECASE,
)
MARKDOWN_HTML_ENABLED_PATTERN = re.compile(
    r"(?:html|allowDangerousHtml)\s*:\s*true",
    re.IGNORECASE,
)
AUTOESCAPE_DISABLED_PATTERN = re.compile(
    r"autoescape\s*:\s*false",
    re.IGNORECASE,
)
REMOTE_PASSTHROUGH_PATTERN = re.compile(
    r"addPassthroughCopy\s*\(\s*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:require|import)\s*\(\s*['\"]https?://",
    re.IGNORECASE,
)
DYNAMIC_PARTIALS_PATTERN = re.compile(
    r"dynamicPartials\s*:\s*true",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
FUNCTION_CONSTRUCTOR_PATTERN = re.compile(r"\bFunction\s*\(")
GLOBAL_DATA_SECRET_PATTERN = re.compile(
    r"addGlobalData\s*\(\s*['\"](?:secret|token|apiKey|password)",
    re.IGNORECASE,
)
GLOBAL_DATA_HARDCODED_SECRET_PATTERN = re.compile(
    r"addGlobalData\s*\([^)]*['\"][^'\"${}][^'\"]*['\"]",
    re.IGNORECASE,
)
WATCH_MODE_PATTERN = re.compile(
    r"(?:watch|serve)\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class EleventyFinding:
    """A security or best-practice issue in an Eleventy configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class EleventyInfo:
    """Parsed metadata about an Eleventy configuration file."""

    path: str
    lines: int = 0
    input_dir: str | None = None
    output_dir: str | None = None
    has_server_options: bool = False
    has_passthrough: bool = False


@dataclass
class EleventyStats:
    """Aggregate Eleventy analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_eleventy_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in ELEVENTY_MARKERS)


def _is_eleventy_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES and not path.name.startswith("eleventy.config."):
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_eleventy_config(content)


class EleventyAnalyzer:
    """Audit Eleventy configuration for documentation security and hygiene risks.

    Scans .eleventy.js and eleventy.config.* for hardcoded secrets, exposed dev
    servers, disabled template autoescape, remote passthrough copies, and unsafe
    markdown rendering settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[EleventyFinding] | None = None
        self._stats: EleventyStats | None = None
        self._infos: list[EleventyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Eleventy configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_eleventy_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("eleventy.config.*")):
            if path.is_file() and _is_eleventy_config(path) and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob(".eleventy.*")):
            if path.is_file() and _is_eleventy_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[EleventyFinding],
        info: EleventyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if "input:" in stripped or "input :" in stripped:
            value = stripped.split(":", 1)[1].strip().strip("'\",")
            if value:
                info.input_dir = value

        if "output:" in stripped or "output :" in stripped:
            value = stripped.split(":", 1)[1].strip().strip("'\",")
            if value:
                info.output_dir = value

        if "setServerOptions" in stripped:
            info.has_server_options = True

        if "addPassthroughCopy" in stripped:
            info.has_passthrough = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Eleventy config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Eleventy config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Eleventy config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (SHOW_ALL_HOSTS_PATTERN, "show_all_hosts", "medium", "showAllHosts: true exposes dev server on all interfaces — use localhost"),
            (BIND_ALL_INTERFACES_PATTERN, "bind_all_interfaces", "medium", "server binds to all interfaces — use 127.0.0.1 for local dev"),
            (MARKDOWN_HTML_ENABLED_PATTERN, "markdown_html_enabled", "high", "markdown html: true allows raw HTML — XSS risk in rendered content"),
            (AUTOESCAPE_DISABLED_PATTERN, "autoescape_disabled", "high", "template autoescape disabled — XSS risk in rendered templates"),
            (REMOTE_PASSTHROUGH_PATTERN, "remote_passthrough", "medium", "addPassthroughCopy loads remote asset — self-host or pin trusted sources"),
            (REMOTE_PLUGIN_PATTERN, "remote_plugin", "high", "remote module import in Eleventy config — only load trusted local packages"),
            (DYNAMIC_PARTIALS_PATTERN, "dynamic_partials", "low", "dynamicPartials: true may allow template injection — review partial sources"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Eleventy config — avoid dynamic code execution in config"),
            (FUNCTION_CONSTRUCTOR_PATTERN, "eval_exec", "high", "Function constructor in Eleventy config — avoid dynamic code execution in config"),
            (GLOBAL_DATA_SECRET_PATTERN, "global_data_secret", "high", "addGlobalData exposes secret to all templates — use server-side env vars"),
            (GLOBAL_DATA_HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in addGlobalData — use env vars or CI secrets"),
            (WATCH_MODE_PATTERN, "watch_mode", "low", "watch/serve enabled in config — ensure not deployed to production"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    EleventyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[EleventyFinding], EleventyInfo]:
        findings: list[EleventyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, EleventyInfo(path=rel)

        info = EleventyInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[EleventyFinding]:
        """Scan Eleventy configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[EleventyFinding] = []
        infos: list[EleventyInfo] = []
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
        self._stats = EleventyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> EleventyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[EleventyInfo]:
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
        """Scaffold a hardened Eleventy configuration template."""
        return """\
// Generated by DevAI EleventyAnalyzer
module.exports = function (eleventyConfig) {
  eleventyConfig.setServerOptions({
    showAllHosts: false,
    host: "127.0.0.1",
  });

  eleventyConfig.setLiquidOptions({
    dynamicPartials: false,
  });

  eleventyConfig.setNunjucksEnvironmentOptions({
    autoescape: true,
  });

  eleventyConfig.amendLibrary("md", (mdLib) => {
    mdLib.set({ html: false, linkify: true });
  });

  return {
    dir: {
      input: "src",
      output: "dist",
      includes: "_includes",
      data: "_data",
    },
    htmlTemplateEngine: "liquid",
    markdownTemplateEngine: "liquid",
    pathPrefix: "/",
  };
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Eleventy configs: none found"
        return (
            f"Eleventy configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Eleventy analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
