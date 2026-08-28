"""NuxtAnalyzer — audit Nuxt configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

NUXT_CONFIG_NAMES = (
    "nuxt.config.ts",
    "nuxt.config.js",
    "nuxt.config.mjs",
    "nuxt.config.cjs",
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
    r"host\s*:\s*(?:true|['\"]0\.0\.0\.0['\"]|['\"]::['\"])",
    re.IGNORECASE,
)
DEVTOOLS_ENABLED_PATTERN = re.compile(
    r"devtools\s*:\s*(?:true|\{[^}]*enabled\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
SOURCEMAP_ENABLED_PATTERN = re.compile(
    r"sourcemap\s*:\s*(?:true|\{[^}]*(?:server|client)\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
CSP_DISABLED_PATTERN = re.compile(
    r"contentSecurityPolicy\s*:\s*false",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|allowedOrigins)\s*:\s*['\"]\*['\"]|"
    r"cors\s*:\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)
REWRITE_INTERNAL_PATTERN = re.compile(
    r"(?:destination|source|target|proxy)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
REMOTE_PATTERN_WILDCARD_PATTERN = re.compile(
    r"hostname\s*:\s*['\"]\*['\"]",
    re.IGNORECASE,
)
REMOTE_PATTERN_HTTP_PATTERN = re.compile(
    r"protocol\s*:\s*['\"]http['\"]",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
FS_ALLOW_PERMISSIVE_PATTERN = re.compile(
    r"fs\s*:\s*\{[^}]*allow\s*:\s*\[[^\]]*(?:\.\./|['\"]\.\.['\"]|['\"]\*['\"])",
    re.IGNORECASE | re.DOTALL,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
RUNTIME_CONFIG_SECRET_PATTERN = re.compile(
    r"(?:apiSecret|authSecret|jwtSecret|sessionSecret|privateKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PUBLIC_RUNTIME_HTTP_PATTERN = re.compile(
    r"public\s*:\s*\{[^}]*(?:apiBase|baseURL|siteUrl)\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE | re.DOTALL,
)
SSR_DISABLED_PATTERN = re.compile(
    r"ssr\s*:\s*false",
    re.IGNORECASE,
)
TELEMETRY_ENABLED_PATTERN = re.compile(
    r"telemetry\s*:\s*(?:true|\{[^}]*enabled\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
ROUTE_RULE_PROXY_PATTERN = re.compile(
    r"routeRules\s*:\s*\{[^}]*proxy\s*:\s*['\"]https?://",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class NuxtFinding:
    """A security or best-practice issue in a Nuxt configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NuxtInfo:
    """Parsed metadata about a Nuxt configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_nitro: bool = False
    has_vite: bool = False
    has_runtime_config: bool = False
    has_route_rules: bool = False
    has_security: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class NuxtStats:
    """Aggregate Nuxt analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nuxt_file(path: Path) -> bool:
    return path.name in NUXT_CONFIG_NAMES or path.name.startswith("nuxt.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_nuxt_project(root: Path) -> bool:
    if any((root / name).exists() for name in NUXT_CONFIG_NAMES):
        return True
    for pattern in ("nuxt.config.*",):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and "nuxt" in deps:
                return True
        except json.JSONDecodeError:
            pass
    return False


class NuxtAnalyzer:
    """Audit Nuxt configuration for security and production risks.

    Scans nuxt.config.* files for hardcoded secrets, exposed dev servers,
    runtimeConfig leaks, internal proxy targets, disabled CSP, production
    sourcemaps, and enabled devtools in production builds.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NuxtFinding] | None = None
        self._stats: NuxtStats | None = None
        self._infos: list[NuxtInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Nuxt configuration paths found in the project."""
        found: list[Path] = []
        for name in NUXT_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("nuxt.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_nuxt_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NuxtFinding],
        info: NuxtInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("nitro", "vite", "runtimeConfig", "routeRules", "security", "devtools"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                attr = section.lower().replace("runtimeconfig", "runtime_config").replace(
                    "routerules", "route_rules"
                )
                if hasattr(info, f"has_{attr}"):
                    setattr(info, f"has_{attr}", True)
                elif section == "runtimeConfig":
                    info.has_runtime_config = True
                elif section == "routeRules":
                    info.has_route_rules = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Nuxt config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Nuxt config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Nuxt config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Nuxt config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Nuxt config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Nuxt config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (RUNTIME_CONFIG_SECRET_PATTERN, "runtime_config_secret", "high",
             "secret in runtimeConfig — use NUXT_* environment variables at runtime"),
            (REWRITE_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy/redirect to internal IP — SSRF risk in dev and production"),
            (PUBLIC_RUNTIME_HTTP_PATTERN, "public_runtime_http", "high",
             "public runtimeConfig uses HTTP — client-side API calls may be insecure"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost in dev"),
            (DEVTOOLS_ENABLED_PATTERN, "devtools_enabled", "medium",
             "devtools enabled — may expose debug UI in production builds"),
            (SOURCEMAP_ENABLED_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "contentSecurityPolicy disabled — XSS protection weakened"),
            (CORS_WILDCARD_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access dev server or APIs"),
            (REMOTE_PATTERN_WILDCARD_PATTERN, "remote_pattern_wildcard", "medium",
             "image or remote pattern hostname set to * — allows any origin"),
            (REMOTE_PATTERN_HTTP_PATTERN, "remote_pattern_http", "medium",
             "remote pattern uses HTTP — resources loaded over insecure transport"),
            (FS_ALLOW_PERMISSIVE_PATTERN, "fs_allow_permissive", "medium",
             "vite.server.fs.allow is permissive — dev server may read sensitive paths"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (ROUTE_RULE_PROXY_PATTERN, "route_rule_proxy", "medium",
             "nitro.routeRules uses proxy — verify targets are not internal IPs"),
            (SSR_DISABLED_PATTERN, "ssr_disabled", "low",
             "ssr disabled — client-only rendering may weaken SEO and initial-load security"),
            (TELEMETRY_ENABLED_PATTERN, "telemetry_enabled", "low",
             "telemetry enabled — may send usage data to third parties"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    NuxtFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[NuxtFinding], NuxtInfo]:
        findings: list[NuxtFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NuxtInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = NuxtInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[NuxtFinding]:
        """Scan Nuxt configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NuxtFinding] = []
        infos: list[NuxtInfo] = []
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
        self._stats = NuxtStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NuxtStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NuxtInfo]:
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
        """Scaffold a hardened nuxt.config.ts template."""
        return """\
// Generated by DevAI NuxtAnalyzer
export default defineNuxtConfig({
  devtools: { enabled: false },
  ssr: true,
  telemetry: { enabled: false },
  sourcemap: { server: false, client: false },
  runtimeConfig: {
  // Private keys (server-only) — set via NUXT_* env vars at runtime
    apiSecret: '',
    public: {
      apiBase: 'https://api.example.com',
    },
  },
  nitro: {
    routeRules: {
      '/api/**': { cors: false },
    },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
  },
  security: {
    headers: {
      contentSecurityPolicy: true,
      crossOriginResourcePolicy: 'same-origin',
    },
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nuxt: no configuration files found"
        return (
            f"Nuxt: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Nuxt configuration analysis:",
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
