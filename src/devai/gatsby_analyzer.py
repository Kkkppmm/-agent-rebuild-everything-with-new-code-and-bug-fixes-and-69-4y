"""GatsbyAnalyzer — audit Gatsby configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

GATSBY_CONFIG_NAMES = (
    "gatsby-config.js",
    "gatsby-config.mjs",
    "gatsby-config.ts",
    "gatsby-config.cjs",
    "gatsby-node.js",
    "gatsby-node.mjs",
    "gatsby-node.ts",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
UNSAFE_ENV_PATTERN = re.compile(
    r"(?:process\.env\.(?:NODE_TLS_REJECT_UNAUTHORIZED|ALLOW_INSECURE))\s*=\s*[\"']?0[\"']?",
    re.IGNORECASE,
)
HOST_EXPOSED_PATTERN = re.compile(
    r"host\s*:\s*(?:['\"]0\.0\.0\.0['\"]|['\"]::['\"])",
    re.IGNORECASE,
)
SITE_METADATA_HTTP_PATTERN = re.compile(
    r"(?:siteUrl|url)\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
SITE_METADATA_SECRET_PATTERN = re.compile(
    r"(?:apiKey|apiToken|accessToken|authToken|privateKey|secretKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:proxy|target|rewrite|url)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
SOURCEMAP_TRUE_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap|GENERATE_SOURCEMAP)\s*[=:]\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
PLUGIN_SECRET_PATTERN = re.compile(
    r"(?:accessKeyId|secretAccessKey|accessToken|apiToken|authToken|privateKey|clientSecret)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
GRAPHQL_PLAYGROUND_PATTERN = re.compile(
    r"(?:graphqlPlayground|GATSBY_GRAPHQL_IDE)\s*[=:]\s*(?:true|['\"]enable['\"])",
    re.IGNORECASE,
)
TRAILING_SLASH_ALWAYS_PATTERN = re.compile(
    r"trailingSlash\s*:\s*['\"]always['\"]",
    re.IGNORECASE,
)
PATH_PREFIX_RELATIVE_PATTERN = re.compile(
    r"pathPrefix\s*:\s*['\"]\.\./",
    re.IGNORECASE,
)
DEVELOP_MIDDLEWARE_PATTERN = re.compile(
    r"onCreateDevServer|developMiddleware",
    re.IGNORECASE,
)
CORS_OPEN_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|allowedOrigins)\s*:\s*['\"]\*['\"]",
    re.IGNORECASE,
)


@dataclass
class GatsbyFinding:
    """A security or best-practice issue in a Gatsby configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class GatsbyInfo:
    """Parsed metadata about a Gatsby configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_plugins: bool = False
    has_site_metadata: bool = False
    has_proxy: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class GatsbyStats:
    """Aggregate Gatsby analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gatsby_file(path: Path) -> bool:
    return (
        path.name in GATSBY_CONFIG_NAMES
        or path.name.startswith("gatsby-config.")
        or path.name.startswith("gatsby-node.")
    )


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_gatsby_project(root: Path) -> bool:
    if any((root / name).exists() for name in GATSBY_CONFIG_NAMES):
        return True
    for pattern in ("gatsby-config.*", "gatsby-node.*"):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and "gatsby" in deps:
                return True
        except json.JSONDecodeError:
            pass
    return False


class GatsbyAnalyzer:
    """Audit Gatsby configuration for security and production risks.

    Scans gatsby-config.* and gatsby-node.* files for hardcoded secrets,
    HTTP site URLs, exposed GraphQL playground, internal proxy targets,
    and plugin credentials.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GatsbyFinding] | None = None
        self._stats: GatsbyStats | None = None
        self._infos: list[GatsbyInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Gatsby configuration paths found in the project."""
        found: list[Path] = []
        for name in GATSBY_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("gatsby-config.*", "gatsby-node.*"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_gatsby_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GatsbyFinding],
        info: GatsbyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("plugins", "siteMetadata", "proxy", "developMiddleware"):
            if section in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "plugins":
                    info.has_plugins = True
                elif section == "siteMetadata":
                    info.has_site_metadata = True
                elif section == "proxy":
                    info.has_proxy = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Gatsby config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Gatsby config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Gatsby config — use HTTPS"),
            (SITE_METADATA_HTTP_PATTERN, "site_url_http", "high",
             "siteUrl uses HTTP — canonical URLs should use HTTPS in production"),
            (SITE_METADATA_SECRET_PATTERN, "site_metadata_secret", "high",
             "secret in siteMetadata — use GATSBY_* environment variables"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Gatsby config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Gatsby config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Gatsby config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (PLUGIN_SECRET_PATTERN, "plugin_secret", "high",
             "credential in plugin options — use environment variables or secret stores"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy target to internal IP — SSRF risk in dev server"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost in dev"),
            (GRAPHQL_PLAYGROUND_PATTERN, "graphql_playground", "medium",
             "GraphQL playground enabled — may expose schema in production"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access dev server or APIs"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (SOURCEMAP_TRUE_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (PATH_PREFIX_RELATIVE_PATTERN, "path_prefix_relative", "medium",
             "pathPrefix uses relative parent path — may expose files outside project root"),
            (DEVELOP_MIDDLEWARE_PATTERN, "develop_middleware", "medium",
             "custom develop middleware — verify no SSRF or auth bypass"),
            (TRAILING_SLASH_ALWAYS_PATTERN, "trailing_slash_always", "low",
             "trailingSlash set to always — may cause redirect loops with misconfigured proxies"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    GatsbyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[GatsbyFinding], GatsbyInfo]:
        findings: list[GatsbyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GatsbyInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = GatsbyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[GatsbyFinding]:
        """Scan Gatsby configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GatsbyFinding] = []
        infos: list[GatsbyInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = GatsbyStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GatsbyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GatsbyInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold a hardened gatsby-config.js template."""
        return """\
// Generated by DevAI GatsbyAnalyzer
module.exports = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
  },
  plugins: [],
  proxy: [],
  flags: {
    FAST_DEV: false,
  },
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Gatsby: no configuration files found"
        return (
            f"Gatsby: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Gatsby configuration analysis:",
            f"  config files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"sections={','.join(info.sections) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
