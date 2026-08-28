"""NuxtAnalyzer — audit Nuxt configuration files for security and deployment risks."""

from __future__ import annotations

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
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SSR_FALSE_PATTERN = re.compile(
    r"\bssr\s*:\s*false\b",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|access-control-allow-origin)\s*['\"]?\s*:\s*['\"]?\*['\"]?",
    re.IGNORECASE,
)
CORS_HEADERS_WILDCARD_PATTERN = re.compile(
    r"(?:cors|headers)\s*:\s*\{[^}]*['\"]?\*['\"]?",
    re.IGNORECASE,
)
ALLOWED_HOSTS_ALL_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:true|['\"]all['\"]|['\"]\*['\"])",
    re.IGNORECASE,
)
DISABLED_SECURITY_HEADERS_PATTERN = re.compile(
    r"(?:xssProtection|contentSecurityPolicy|crossOriginEmbedderPolicy|"
    r"crossOriginOpenerPolicy|crossOriginResourcePolicy|strictTransportSecurity|"
    r"referrerPolicy)\s*:\s*(?:false|null|0|['\"]?(?:off|false)['\"]?)",
    re.IGNORECASE,
)
PUBLIC_RUNTIME_SECRET_PATTERN = re.compile(
    r"runtimeConfig\s*:\s*\{[^}]*public\s*:\s*\{[^}]*"
    r"(?:password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE | re.DOTALL,
)
PUBLIC_CONFIG_SECRET_PATTERN = re.compile(
    r"public\s*:\s*\{[^}]*"
    r"(?:password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
DEV_PROXY_PATTERN = re.compile(
    r"devProxy\s*:\s*\{",
    re.IGNORECASE,
)
REMOTE_MODULE_PATTERN = re.compile(
    r"(?:modules|extends)\s*:\s*\[[^\]]*https?://",
    re.IGNORECASE | re.DOTALL,
)
NITRO_UNSAFE_INLINE_PATTERN = re.compile(
    r"(?:unsafe-inline|unsafe-eval)",
    re.IGNORECASE,
)
REMOTE_MODULE_URL_PATTERN = re.compile(
    r"['\"]https?://[^'\"]+['\"]",
    re.IGNORECASE,
)
CLIENT_SOURCEMAP_TRUE_PATTERN = re.compile(
    r"client\s*:\s*true\b",
    re.IGNORECASE,
)
SOURCEMAP_BLOCK_PATTERN = re.compile(
    r"^\s*sourcemap\s*:\s*\{",
    re.IGNORECASE,
)
TELEMETRY_DISABLED_PATTERN = re.compile(
    r"telemetry\s*:\s*false",
    re.IGNORECASE,
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
    ssr_enabled: bool | None = None
    has_runtime_config: bool = False
    has_dev_proxy: bool = False
    module_count: int = 0


@dataclass
class NuxtStats:
    """Aggregate Nuxt analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nuxt_config(path: Path) -> bool:
    return path.name in NUXT_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".ts":
        return "typescript"
    if suffix == ".mjs":
        return "mjs"
    if suffix == ".cjs":
        return "cjs"
    return "javascript"


class NuxtAnalyzer:
    """Audit Nuxt configuration for security and deployment risks.

    Scans nuxt.config.ts/js/mjs for disabled SSR, exposed runtime secrets,
    permissive CORS, disabled security headers, dev proxy exposure,
    remote module URLs, and hardcoded credentials.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NuxtFinding] | None = None
        self._stats: NuxtStats | None = None
        self._infos: list[NuxtInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Nuxt configuration paths found in the project."""
        found: list[Path] = []
        for name in NUXT_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("nuxt.config.*")):
            if path.is_file() and path not in found and _is_nuxt_config(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NuxtFinding],
        info: NuxtInfo,
        *,
        in_sourcemap: bool = False,
    ) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return in_sourcemap

        if SOURCEMAP_BLOCK_PATTERN.search(line):
            in_sourcemap = True
        elif re.match(r"^\s*\w", line) and not line.startswith(" "):
            in_sourcemap = False

        if re.search(r"\bssr\s*:\s*true\b", line, re.IGNORECASE):
            info.ssr_enabled = True
        if SSR_FALSE_PATTERN.search(line):
            info.ssr_enabled = False
            findings.append(
                NuxtFinding(
                    kind="ssr_disabled",
                    severity="medium",
                    message="SSR disabled — SPA-only mode may expose client-side secrets and hurt SEO",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if re.search(r"\bruntimeConfig\b", line, re.IGNORECASE):
            info.has_runtime_config = True

        if DEV_PROXY_PATTERN.search(line):
            info.has_dev_proxy = True
            findings.append(
                NuxtFinding(
                    kind="dev_proxy",
                    severity="medium",
                    message="devProxy configured — ensure internal services are not exposed in production builds",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        module_match = re.findall(r"['\"](?:@nuxt/|nuxt-|[^'\"./][^'\"]*)['\"]", line)
        if re.search(r"\bmodules\s*:", line, re.IGNORECASE):
            info.module_count += len(module_match)

        if CORS_WILDCARD_PATTERN.search(line) or CORS_HEADERS_WILDCARD_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="cors_wildcard",
                    severity="high",
                    message="wildcard CORS origin — restrict allowed origins to trusted domains",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if ALLOWED_HOSTS_ALL_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="allowed_hosts_all",
                    severity="high",
                    message="allowedHosts set to all — restrict Vite dev server host allowlist",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if DISABLED_SECURITY_HEADERS_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="security_headers_disabled",
                    severity="high",
                    message="Nitro security header disabled — keep CSP, HSTS, and XSS protection enabled",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if NITRO_UNSAFE_INLINE_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="csp_unsafe_inline",
                    severity="medium",
                    message="CSP allows unsafe-inline or unsafe-eval — tighten content security policy",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if PUBLIC_CONFIG_SECRET_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="public_runtime_secret",
                    severity="high",
                    message="secret in runtimeConfig.public — move sensitive values to server-only runtimeConfig",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if REMOTE_MODULE_URL_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="remote_module",
                    severity="high",
                    message="remote module URL — pin to trusted sources and verify integrity",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if in_sourcemap and CLIENT_SOURCEMAP_TRUE_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="client_sourcemap",
                    severity="medium",
                    message="client sourcemaps enabled — disable in production to avoid source disclosure",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in Nuxt config — use runtimeConfig and environment variables",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )
        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Nuxt config — rotate and use secrets management",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )
        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="SCM credentials in Nuxt config — use deploy keys or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )
        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Nuxt config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )
        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell pattern in Nuxt config — avoid eval, sudo, and curl|sh",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        return in_sourcemap

    def _analyze_file(self, path: Path) -> tuple[list[NuxtFinding], NuxtInfo]:
        findings: list[NuxtFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, NuxtInfo(path=rel)

        info = NuxtInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_sourcemap = False

        if PUBLIC_RUNTIME_SECRET_PATTERN.search(content):
            findings.append(
                NuxtFinding(
                    kind="public_runtime_secret",
                    severity="high",
                    message="secret in runtimeConfig.public block — move sensitive values to server-only runtimeConfig",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        for lineno, line in enumerate(raw_lines, start=1):
            in_sourcemap = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_sourcemap=in_sourcemap,
            )

        return findings, info

    def analyze(self) -> list[NuxtFinding]:
        """Scan Nuxt configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NuxtFinding] = []
        infos: list[NuxtInfo] = []
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
        self._stats = NuxtStats(
            config_files=len(paths),
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
        """Scaffold a hardened Nuxt configuration template."""
        return """\
// Generated by DevAI NuxtAnalyzer
// Nuxt 3 — https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  ssr: true,

  runtimeConfig: {
    apiSecret: process.env.NUXT_API_SECRET,
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || '/api',
    },
  },

  nitro: {
    routeRules: {
      '/**': {
        headers: {
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'strict-origin-when-cross-origin',
        },
      },
    },
  },

  vite: {
    server: {
      allowedHosts: ['localhost'],
    },
  },

  sourcemap: {
    server: true,
    client: false,
  },
})
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "nuxt configs: none found"
        return (
            f"nuxt configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "nuxt analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ssr = "default" if info.ssr_enabled is None else str(info.ssr_enabled).lower()
            lines.append(
                f"  - {info.path}: kind={info.file_kind}, ssr={ssr}, modules={info.module_count}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
