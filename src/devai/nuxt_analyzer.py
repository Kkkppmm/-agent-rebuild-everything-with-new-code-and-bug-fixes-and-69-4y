"""NuxtAnalyzer — audit Nuxt config files for security and deployment risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "nuxt.config.ts",
    "nuxt.config.js",
    "nuxt.config.mjs",
    "nuxt.config.mts",
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
DEVTOOLS_ENABLED_PATTERN = re.compile(
    r"devtools\s*:\s*\{[^}]*enabled\s*:\s*true",
    re.IGNORECASE | re.DOTALL,
)
DEVTOOLS_SIMPLE_ENABLED_PATTERN = re.compile(
    r"devtools\s*:\s*\{\s*enabled\s*:\s*true\s*\}",
    re.IGNORECASE,
)
SOURCEMAP_ENABLED_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap)\s*:\s*true\b",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:cors|access-control-allow-origin)\s*[:=]\s*[\"']\*[\"']",
    re.IGNORECASE,
)
ALLOWED_HOSTS_WILDCARD_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:true|\[[^\]]*[\"']\*[\"'])",
    re.IGNORECASE,
)
PUBLIC_SECRET_PATTERN = re.compile(
    r"runtimeConfig\s*:\s*\{[^}]*public\s*:\s*\{[^}]*"
    r"(?:password|secret|api[_-]?key|token|private[_-]?key)",
    re.IGNORECASE | re.DOTALL,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"(?:csrf|security)\s*:\s*(?:false|\{[^}]*enabled\s*:\s*false)",
    re.IGNORECASE | re.DOTALL,
)
SSR_DISABLED_PATTERN = re.compile(
    r"\bssr\s*:\s*false\b",
    re.IGNORECASE,
)
NITRO_PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:proxy|routeRules)\s*:\s*\{[^}]*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.)",
    re.IGNORECASE | re.DOTALL,
)
PROXY_INTERNAL_URL_PATTERN = re.compile(
    r"proxy\s*:\s*['\"]https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.)",
    re.IGNORECASE,
)
TLS_REJECT_DISABLED_PATTERN = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0[\"']?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
TELEMETRY_ENABLED_PATTERN = re.compile(
    r"telemetry\s*:\s*(?:true|\{[^}]*enabled\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
EXPERIMENTAL_UNSAFE_PATTERN = re.compile(
    r"experimental\s*:\s*\{[^}]*(?:wasm|payloadExtraction|inlineSSRStyles)\s*:\s*true",
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
    ssr_enabled: bool | None = None
    devtools_enabled: bool = False
    has_runtime_config: bool = False
    has_public_runtime_config: bool = False


@dataclass
class NuxtStats:
    """Aggregate Nuxt analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nuxt_config(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith("nuxt.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith((".ts", ".mts")):
        return "typescript"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    return "unknown"


class NuxtAnalyzer:
    """Audit Nuxt configuration for security and deployment risks.

    Scans nuxt.config.* for hardcoded secrets in runtimeConfig, devtools enabled
    in production configs, permissive CORS/allowedHosts, disabled SSR/CSRF, source
    maps in production, Nitro proxy rules to internal hosts, and TLS verification bypass.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[NuxtFinding] | None = None
        self._stats: NuxtStats | None = None
        self._infos: list[NuxtInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Nuxt configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
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
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if re.search(r"\bssr\s*:\s*true\b", stripped, re.IGNORECASE):
            info.ssr_enabled = True
        if SSR_DISABLED_PATTERN.search(stripped):
            info.ssr_enabled = False
            findings.append(
                NuxtFinding(
                    kind="ssr_disabled",
                    severity="medium",
                    message="ssr=false disables server rendering — verify SPA security controls and SEO needs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r"runtimeConfig\s*:", stripped, re.IGNORECASE):
            info.has_runtime_config = True
        if re.search(r"public\s*:\s*\{", stripped, re.IGNORECASE):
            info.has_public_runtime_config = True

        if DEVTOOLS_ENABLED_PATTERN.search(stripped) or DEVTOOLS_SIMPLE_ENABLED_PATTERN.search(stripped):
            info.devtools_enabled = True
            findings.append(
                NuxtFinding(
                    kind="devtools_enabled",
                    severity="medium",
                    message="devtools enabled — disable in production builds to avoid exposing internals",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SOURCEMAP_ENABLED_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="sourcemap_enabled",
                    severity="medium",
                    message="source maps enabled — disable in production to avoid leaking source code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CORS_WILDCARD_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="cors_wildcard",
                    severity="high",
                    message="CORS allows all origins (*) — restrict allowed origins in production",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOWED_HOSTS_WILDCARD_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="allowed_hosts_wildcard",
                    severity="high",
                    message="allowedHosts is permissive — restrict dev server host allowlist",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PUBLIC_SECRET_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="public_secret",
                    severity="high",
                    message="runtimeConfig.public exposes secret-like keys — keep secrets server-only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CSRF_DISABLED_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="csrf_disabled",
                    severity="high",
                    message="CSRF/security protections disabled — enable request protections for mutations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NITRO_PROXY_INTERNAL_PATTERN.search(stripped) or PROXY_INTERNAL_URL_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="nitro_proxy_internal",
                    severity="medium",
                    message="Nitro proxy/routeRules target internal hosts — verify SSRF protections",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_REJECT_DISABLED_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="tls_verification_disabled",
                    severity="high",
                    message="TLS certificate verification disabled — never disable TLS checks in production",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if (
            not re.search(r"(?:process|import\.meta)\.env", stripped, re.IGNORECASE)
            and (HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line))
        ):
            findings.append(
                NuxtFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Nuxt config — use environment variables or runtimeConfig",
                    path=rel,
                    lineno=lineno,
                    line=line,
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
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                NuxtFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in Nuxt config — avoid remote code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TELEMETRY_ENABLED_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="telemetry_enabled",
                    severity="low",
                    message="Nuxt telemetry enabled — disable if telemetry is not desired in your environment",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXPERIMENTAL_UNSAFE_PATTERN.search(stripped):
            findings.append(
                NuxtFinding(
                    kind="experimental_feature",
                    severity="low",
                    message="experimental Nuxt feature enabled — review security implications before production",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[NuxtFinding], NuxtInfo]:
        findings: list[NuxtFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, NuxtInfo(path=rel)

        info = NuxtInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

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
// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  ssr: true,
  devtools: { enabled: process.env.NODE_ENV !== 'production' },
  sourcemap: { server: false, client: false },
  runtimeConfig: {
    apiSecret: process.env.NUXT_API_SECRET,
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || 'https://api.example.com',
    },
  },
  nitro: {
    routeRules: {
      '/api/**': { cors: false },
    },
  },
  telemetry: false,
})
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Nuxt configs: none found"
        return (
            f"Nuxt configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Nuxt config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ssr = "enabled" if info.ssr_enabled else ("disabled" if info.ssr_enabled is False else "default")
            lines.append(
                f"  - {info.path}: ssr={ssr}, devtools={info.devtools_enabled}, "
                f"runtimeConfig={info.has_runtime_config}"
            )
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
