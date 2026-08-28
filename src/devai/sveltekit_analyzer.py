"""SvelteKitAnalyzer — audit SvelteKit configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SVELTE_CONFIG_NAMES = (
    "svelte.config.js",
    "svelte.config.ts",
    "svelte.config.mjs",
    "svelte.config.cjs",
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
CHECK_ORIGIN_FALSE_PATTERN = re.compile(
    r"checkOrigin\s*:\s*false",
    re.IGNORECASE,
)
CSP_OFF_PATTERN = re.compile(
    r"(?:mode|reportOnly)\s*:\s*(?:false|['\"]off['\"]|['\"]report-only['\"])",
    re.IGNORECASE,
)
CSP_DISABLED_PATTERN = re.compile(
    r"csp\s*:\s*false",
    re.IGNORECASE,
)
INSPECTOR_ENABLED_PATTERN = re.compile(
    r"inspector\s*:\s*(?:true|\{[^}]*enabled\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
SERVICE_WORKER_REGISTER_PATTERN = re.compile(
    r"register\s*:\s*true",
    re.IGNORECASE,
)
PRERENDER_HTTP_PATTERN = re.compile(
    r"origin\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)",
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
FS_ALLOW_PERMISSIVE_PATTERN = re.compile(
    r"fs\s*:\s*\{[^}]*allow\s*:\s*\[[^\]]*(?:\.\./|['\"]\.\.['\"]|['\"]\*['\"])",
    re.IGNORECASE | re.DOTALL,
)
CORS_OPEN_PATTERN = re.compile(
    r"cors\s*:\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|rewrite|destination|proxy)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
SOURCEMAP_ENABLED_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap)\s*:\s*(?:true|['\"]inline['\"]|['\"]hidden['\"])",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
PUBLIC_ENV_SECRET_PATTERN = re.compile(
    r"(?:PUBLIC_[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY))\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
ALLOWED_HOSTS_ALL_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:true|['\"]all['\"])",
    re.IGNORECASE,
)
TRUSTED_ORIGINS_WILDCARD_PATTERN = re.compile(
    r"trustedOrigins\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
VERSION_POLLING_PATTERN = re.compile(
    r"versionPolling\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class SvelteKitFinding:
    """A security or best-practice issue in a SvelteKit configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class SvelteKitInfo:
    """Parsed metadata about a SvelteKit configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_kit: bool = False
    has_vite: bool = False
    has_csrf: bool = False
    has_csp: bool = False
    has_prerender: bool = False
    has_service_worker: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class SvelteKitStats:
    """Aggregate SvelteKit analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_svelte_config(path: Path) -> bool:
    return path.name in SVELTE_CONFIG_NAMES or path.name.startswith("svelte.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_sveltekit_project(root: Path) -> bool:
    if any((root / name).exists() for name in SVELTE_CONFIG_NAMES):
        return True
    for pattern in ("svelte.config.*",):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and (
                "@sveltejs/kit" in deps or "@sveltejs/adapter-node" in deps
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class SvelteKitAnalyzer:
    """Audit SvelteKit configuration for security and production risks.

    Scans svelte.config.* files for disabled CSRF checks, CSP bypass,
    hardcoded secrets, exposed dev servers, internal proxy targets,
    production sourcemaps, and enabled experimental inspector.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SvelteKitFinding] | None = None
        self._stats: SvelteKitStats | None = None
        self._infos: list[SvelteKitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return SvelteKit configuration paths found in the project."""
        found: list[Path] = []
        for name in SVELTE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("svelte.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_svelte_config(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SvelteKitFinding],
        info: SvelteKitInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("kit", "vite", "csrf", "csp", "prerender", "serviceWorker"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "kit":
                    info.has_kit = True
                elif section == "vite":
                    info.has_vite = True
                elif section == "csrf":
                    info.has_csrf = True
                elif section == "csp":
                    info.has_csp = True
                elif section == "prerender":
                    info.has_prerender = True
                elif section == "serviceWorker":
                    info.has_service_worker = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in SvelteKit config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in SvelteKit config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in SvelteKit config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in SvelteKit config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in SvelteKit config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in SvelteKit config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (PUBLIC_ENV_SECRET_PATTERN, "public_env_secret", "high",
             "sensitive value in PUBLIC_* env — client-exposed variables must not hold secrets"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy/redirect to internal IP — SSRF risk in dev and production"),
            (PRERENDER_HTTP_PATTERN, "prerender_http", "high",
             "prerender origin uses HTTP — crawlers may follow insecure links"),
            (CHECK_ORIGIN_FALSE_PATTERN, "check_origin_disabled", "high",
             "CSRF checkOrigin disabled — cross-site request forgery protection weakened"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost in dev"),
            (CSP_OFF_PATTERN, "csp_disabled", "medium",
             "CSP mode disabled or report-only — XSS protection weakened"),
            (CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "CSP disabled in kit config — XSS protection removed"),
            (INSPECTOR_ENABLED_PATTERN, "inspector_enabled", "medium",
             "experimental inspector enabled — may expose debug UI in production"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access dev server or APIs"),
            (REMOTE_PATTERN_WILDCARD_PATTERN, "remote_pattern_wildcard", "medium",
             "image or remote pattern hostname set to * — allows any origin"),
            (REMOTE_PATTERN_HTTP_PATTERN, "remote_pattern_http", "medium",
             "remote pattern uses HTTP — resources loaded over insecure transport"),
            (FS_ALLOW_PERMISSIVE_PATTERN, "fs_allow_permissive", "medium",
             "vite.server.fs.allow is permissive — dev server may read sensitive paths"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (ALLOWED_HOSTS_ALL_PATTERN, "allowed_hosts_all", "medium",
             "allowedHosts set to all — dev server accepts requests from any host"),
            (TRUSTED_ORIGINS_WILDCARD_PATTERN, "trusted_origins_wildcard", "medium",
             "trustedOrigins includes * — any origin trusted for CSRF checks"),
            (SOURCEMAP_ENABLED_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (SERVICE_WORKER_REGISTER_PATTERN, "service_worker_enabled", "low",
             "service worker registration enabled — verify scope and caching policy"),
            (VERSION_POLLING_PATTERN, "version_polling_enabled", "low",
             "version polling enabled — may leak deployment timing to clients"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    SvelteKitFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[SvelteKitFinding], SvelteKitInfo]:
        findings: list[SvelteKitFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, SvelteKitInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = SvelteKitInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[SvelteKitFinding]:
        """Scan SvelteKit configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SvelteKitFinding] = []
        infos: list[SvelteKitInfo] = []
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
        self._stats = SvelteKitStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SvelteKitStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SvelteKitInfo]:
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
        """Scaffold a hardened svelte.config.js template."""
        return """\
// Generated by DevAI SvelteKitAnalyzer
import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: true },
    csp: { mode: 'auto' },
    env: { publicPrefix: 'PUBLIC_' },
    prerender: { origin: 'https://example.com' },
    serviceWorker: { register: false },
    experimental: { inspector: false },
    version: { pollInterval: 0 },
  },
  vite: {
    server: {
      host: '127.0.0.1',
      fs: { allow: ['.'] },
      cors: false,
    },
  },
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "SvelteKit: no configuration files found"
        return (
            f"SvelteKit: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "SvelteKit configuration analysis:",
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
