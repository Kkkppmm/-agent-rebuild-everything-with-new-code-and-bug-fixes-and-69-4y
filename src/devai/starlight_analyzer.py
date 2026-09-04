"""StarlightAnalyzer — audit Astro Starlight docs configs for security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ASTRO_CONFIG_NAMES = (
    "astro.config.mjs",
    "astro.config.js",
    "astro.config.ts",
    "astro.config.cjs",
)

STARLIGHT_MARKERS = (
    "@astrojs/starlight",
    "starlight(",
    "starlight({",
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
    r"://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
REMOTE_HEAD_SCRIPT_PATTERN = re.compile(
    r"(?:tag\s*:\s*['\"]script['\"]|attrs\s*:\s*\{[^\}]*src\s*:\s*['\"]https?://)",
    re.IGNORECASE,
)
REMOTE_HEAD_SRC_PATTERN = re.compile(
    r"src\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_CUSTOM_CSS_PATTERN = re.compile(
    r"customCss\s*:\s*\[[^\]]*['\"]https?://",
    re.IGNORECASE,
)
REMOTE_LOGO_PATTERN = re.compile(
    r"logo\s*:\s*\{[^\}]*src\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
EDIT_LINK_HTTP_PATTERN = re.compile(
    r"baseUrl\s*:\s*['\"]http://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec|Function)\s*\(", re.IGNORECASE)
EXPRESSIVE_CODE_RAW_PATTERN = re.compile(
    r"(?:allowDangerousHtml|rehypeRaw)\s*:\s*true",
    re.IGNORECASE,
)
COMPONENTS_REMOTE_PATTERN = re.compile(
    r"(?:Header|Footer|Banner|PageFrame|SiteTitle|Search|ThemeSelect|SocialIcons)\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
ROUTE_MIDDLEWARE_PATTERN = re.compile(
    r"routeMiddleware\s*:\s*\[[^\]]*(?:eval|Function|https?://)",
    re.IGNORECASE,
)
SOCIAL_CREDENTIAL_PATTERN = re.compile(
    r"://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
FAVICON_HTTP_PATTERN = re.compile(
    r"favicon\s*:\s*['\"]http://",
    re.IGNORECASE,
)
DEFAULT_LOCALE_WILDCARD_PATTERN = re.compile(
    r"defaultLocale\s*:\s*['\"]\*['\"]",
    re.IGNORECASE,
)


@dataclass
class StarlightFinding:
    """A security or best-practice issue in a Starlight configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class StarlightInfo:
    """Parsed metadata about a Starlight configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    has_edit_link: bool = False
    has_social: bool = False
    has_head: bool = False


@dataclass
class StarlightStats:
    """Aggregate Starlight analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_starlight_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in STARLIGHT_MARKERS)


def _is_starlight_config(path: Path) -> bool:
    if path.name not in ASTRO_CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_starlight_config(content)


class StarlightAnalyzer:
    """Audit Astro Starlight documentation configs for security and hygiene risks.

    Scans astro.config.* files that use @astrojs/starlight for hardcoded secrets,
    remote head scripts, insecure edit links, and dangerous expressiveCode settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[StarlightFinding] | None = None
        self._stats: StarlightStats | None = None
        self._infos: list[StarlightInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Starlight configuration paths found in the project."""
        found: list[Path] = []
        for name in ASTRO_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_starlight_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("astro.config.*")):
            if path.is_file() and _is_starlight_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[StarlightFinding],
        info: StarlightInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if stripped.startswith("title:") or stripped.startswith("title :"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\",")

        if "editLink" in stripped:
            info.has_edit_link = True

        if stripped.startswith("social:") or stripped.startswith("social :"):
            info.has_social = True

        if stripped.startswith("head:") or stripped.startswith("head :"):
            info.has_head = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Starlight config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Starlight config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Starlight config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (REMOTE_HEAD_SCRIPT_PATTERN, "remote_head_script", "medium", "head loads remote script — self-host assets or pin trusted CDN versions"),
            (REMOTE_HEAD_SRC_PATTERN, "remote_head_script", "medium", "head loads remote script — self-host assets or pin trusted CDN versions"),
            (REMOTE_CUSTOM_CSS_PATTERN, "remote_custom_css", "low", "customCss loads remote stylesheet — self-host assets"),
            (REMOTE_LOGO_PATTERN, "remote_logo", "low", "logo loads remote image — self-host branding assets"),
            (EDIT_LINK_HTTP_PATTERN, "edit_link_http", "medium", "editLink baseUrl uses HTTP — use HTTPS for edit links"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Starlight config — avoid dynamic code execution in config"),
            (EXPRESSIVE_CODE_RAW_PATTERN, "expressive_code_unsafe", "high", "expressiveCode allows dangerous HTML — XSS risk in rendered code blocks"),
            (COMPONENTS_REMOTE_PATTERN, "components_remote", "medium", "components override loads remote module — pin to trusted package"),
            (ROUTE_MIDDLEWARE_PATTERN, "route_middleware_unsafe", "high", "routeMiddleware uses eval or remote module — avoid dynamic middleware"),
            (SOCIAL_CREDENTIAL_PATTERN, "social_credential", "high", "social link embeds credentials — remove user:pass@ from URLs"),
            (FAVICON_HTTP_PATTERN, "favicon_http", "low", "favicon uses HTTP — use HTTPS for favicon assets"),
            (DEFAULT_LOCALE_WILDCARD_PATTERN, "default_locale_wildcard", "low", "defaultLocale: '*' may expose unintended locales — set explicit locale"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    StarlightFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[StarlightFinding], StarlightInfo]:
        findings: list[StarlightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, StarlightInfo(path=rel)

        info = StarlightInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[StarlightFinding]:
        """Scan Starlight configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[StarlightFinding] = []
        infos: list[StarlightInfo] = []
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
        self._stats = StarlightStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> StarlightStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[StarlightInfo]:
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
        """Scaffold a hardened Astro Starlight configuration template."""
        return """\
// Generated by DevAI StarlightAnalyzer
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  integrations: [
    starlight({
      title: 'My Project Docs',
      description: 'Documentation for my project',
      favicon: '/favicon.svg',
      social: {
        github: 'https://github.com/org/repo',
      },
      editLink: {
        baseUrl: 'https://github.com/org/repo/edit/main/',
      },
      customCss: ['./src/styles/custom.css'],
      head: [],
      components: {},
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
      },
      defaultLocale: 'en',
    }),
  ],
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Starlight configs: none found"
        return (
            f"Starlight configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Starlight analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
