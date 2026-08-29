"""GatsbyAnalyzer — audit Gatsby configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

GATSBY_CONFIG_NAMES = (
    "gatsby-config.js",
    "gatsby-config.ts",
    "gatsby-config.mjs",
    "gatsby-config.cjs",
)
GATSBY_NODE_NAMES = (
    "gatsby-node.js",
    "gatsby-node.ts",
    "gatsby-node.mjs",
    "gatsby-node.cjs",
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
SITE_URL_HTTP_PATTERN = re.compile(
    r"siteUrl\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
    re.IGNORECASE,
)
PLUGIN_SECRET_PATTERN = re.compile(
    r"(?:accessToken|apiKey|api_key|authToken|clientSecret|privateKey|secretKey|"
    r"serviceAccountKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
SITEMETADATA_SECRET_PATTERN = re.compile(
    r"(?:apiKey|api_key|accessToken|authToken|secret|password|token)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:proxy|target|rewrite|destination)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
GRAPHQL_PLAYGROUND_PATTERN = re.compile(
    r"(?:graphqlPlayground|graphiql)\s*:\s*true",
    re.IGNORECASE,
)
HEADERS_CSP_DISABLED_PATTERN = re.compile(
    r"(?:contentSecurityPolicy|content-security-policy|csp)\s*:\s*(?:false|null|['\"]none['\"])|"
    r"Content-Security-Policy['\"].*?value\s*:\s*['\"]none['\"]",
    re.IGNORECASE,
)
HEADERS_CORS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Origin['\"].*?(?:value\s*:\s*['\"]\*['\"]|:\s*['\"]\*['\"])",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:GATSBY_|process\.env\.)(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN)\s*[=:]\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
DEVELOP_MIDDLEWARE_PATTERN = re.compile(
    r"developMiddleware\s*[=:(]",
    re.IGNORECASE,
)
FETCH_INTERNAL_PATTERN = re.compile(
    r"(?:fetch|axios|got|request)\s*\(\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
FLAGS_FAST_DEV_PATTERN = re.compile(
    r"FAST_DEV\s*:\s*true",
    re.IGNORECASE,
)
FLAGS_DEV_SSR_PATTERN = re.compile(
    r"DEV_SSR\s*:\s*true",
    re.IGNORECASE,
)
TRAILING_SLASH_ALWAYS_PATTERN = re.compile(
    r"trailingSlash\s*:\s*['\"]always['\"]",
    re.IGNORECASE,
)
MAPPING_CREDENTIAL_PATTERN = re.compile(
    r"(?:password|secret|token|apiKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PLUGIN_HTTP_PROXY_PATTERN = re.compile(
    r"gatsby-plugin-proxy\s*[,}]|proxy\s*:\s*\{[^}]*target\s*:\s*['\"]http://",
    re.IGNORECASE | re.DOTALL,
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
    has_headers: bool = False
    has_proxy: bool = False
    has_flags: bool = False
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


def _is_gatsby_config_file(path: Path) -> bool:
    return path.name in GATSBY_CONFIG_NAMES or path.name.startswith("gatsby-config.")


def _is_gatsby_node_file(path: Path) -> bool:
    return path.name in GATSBY_NODE_NAMES or path.name.startswith("gatsby-node.")


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
    for pattern in ("gatsby-config.*",):
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

    Scans gatsby-config.* and gatsby-node.* files for hardcoded secrets in
    siteMetadata and plugins, insecure siteUrl, internal proxy targets,
    GraphQL playground exposure, permissive headers, and developMiddleware risks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GatsbyFinding] | None = None
        self._stats: GatsbyStats | None = None
        self._infos: list[GatsbyInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Gatsby configuration paths found in the project."""
        found: list[Path] = []
        is_gatsby = _looks_like_gatsby_project(self.root)

        for name in GATSBY_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("gatsby-config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_gatsby_config_file(path):
                    found.append(path)

        if is_gatsby:
            for name in GATSBY_NODE_NAMES:
                path = self.root / name
                if path.is_file() and path not in found:
                    found.append(path)
            for pattern in ("gatsby-node.*",):
                for path in sorted(self.root.rglob(pattern)):
                    if path.is_file() and path not in found and _is_gatsby_node_file(path):
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

        for section in ("plugins", "siteMetadata", "headers", "proxy", "flags", "mapping"):
            if section in stripped and (":" in stripped or "(" in stripped):
                if section not in info.sections:
                    info.sections.append(section)
                attr = section.lower().replace("sitemetadata", "site_metadata")
                if hasattr(info, f"has_{attr}"):
                    setattr(info, f"has_{attr}", True)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Gatsby config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Gatsby config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Gatsby config — use HTTPS"),
            (SITE_URL_HTTP_PATTERN, "site_url_http", "high",
             "siteUrl uses HTTP — canonical URLs and sitemaps may be insecure"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Gatsby config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Gatsby config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Gatsby config — avoid dynamic code execution"),
            (PLUGIN_SECRET_PATTERN, "plugin_secret", "high",
             "plugin option contains secret — use GATSBY_* env vars or server-side secrets"),
            (SITEMETADATA_SECRET_PATTERN, "site_metadata_secret", "high",
             "secret in siteMetadata — client-visible metadata must not contain secrets"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret in GATSBY_ env — client-exposed values must not be secrets"),
            (MAPPING_CREDENTIAL_PATTERN, "mapping_credential", "high",
             "credential in mapping config — use environment variables"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy to internal IP — SSRF risk during build and develop"),
            (FETCH_INTERNAL_PATTERN, "fetch_internal", "high",
             "fetch to internal IP in gatsby-node — SSRF risk at build time"),
            (GRAPHQL_PLAYGROUND_PATTERN, "graphql_playground", "medium",
             "GraphQL playground enabled — may expose schema in production"),
            (HEADERS_CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "content security policy disabled — XSS protection weakened"),
            (HEADERS_CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
             "Access-Control-Allow-Origin: * — any origin may access APIs"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled — TLS verification bypassed"),
            (PLUGIN_HTTP_PROXY_PATTERN, "plugin_http_proxy", "medium",
             "HTTP proxy plugin target — verify targets are not internal IPs"),
            (DEVELOP_MIDDLEWARE_PATTERN, "develop_middleware", "medium",
             "developMiddleware defined — verify middleware does not expose sensitive routes"),
            (FLAGS_FAST_DEV_PATTERN, "fast_dev_flag", "low",
             "FAST_DEV flag enabled — may skip validation checks in development"),
            (FLAGS_DEV_SSR_PATTERN, "dev_ssr_flag", "low",
             "DEV_SSR flag enabled — experimental SSR may have security gaps"),
            (TRAILING_SLASH_ALWAYS_PATTERN, "trailing_slash_always", "low",
             "trailingSlash always — may cause open-redirect style URL confusion"),
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
        """Scaffold a hardened gatsby-config.ts template."""
        return """\
// Generated by DevAI GatsbyAnalyzer
import type { GatsbyConfig } from 'gatsby';

const config: GatsbyConfig = {
  siteMetadata: {
    title: 'My Site',
    siteUrl: 'https://example.com',
    description: 'A secure Gatsby site',
  },
  plugins: [
    {
      resolve: 'gatsby-plugin-security-headers',
      options: {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: "'self'",
            scriptSrc: "'self'",
            styleSrc: "'self' 'unsafe-inline'",
          },
        },
      },
    },
  ],
  headers: [
    {
      source: '/*',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      ],
    },
  ],
  graphqlTypegen: true,
  trailingSlash: 'never',
};

export default config;
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
