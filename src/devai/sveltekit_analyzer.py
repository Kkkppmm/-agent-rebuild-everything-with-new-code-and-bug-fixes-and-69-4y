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
CSRF_CHECK_ORIGIN_FALSE_PATTERN = re.compile(
    r"checkOrigin\s*:\s*false",
    re.IGNORECASE,
)
CSRF_TRUSTED_WILDCARD_PATTERN = re.compile(
    r"trustedOrigins\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
CSP_DISABLED_PATTERN = re.compile(
    r"(?:csp|contentSecurityPolicy)\s*:\s*(?:false|['\"]unsafe['\"])",
    re.IGNORECASE,
)
CSP_REPORT_ONLY_FALSE_PATTERN = re.compile(
    r"reportOnly\s*:\s*false",
    re.IGNORECASE,
)
CORS_OPEN_PATTERN = re.compile(
    r"cors\s*:\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)
FS_ALLOW_PERMISSIVE_PATTERN = re.compile(
    r"fs\s*:\s*\{[^}]*allow\s*:\s*\[[^\]]*(?:\.\./|['\"]\.\.['\"]|['\"]\*['\"])",
    re.IGNORECASE | re.DOTALL,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|rewrite|proxy|destination)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
ADAPTER_SECRET_PATTERN = re.compile(
    r"(?:accessKeyId|secretAccessKey|apiToken|authToken|privateKey|serviceRoleKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
KIT_ENV_SECRET_PATTERN = re.compile(
    r"(?:public|private)\s*:\s*\{[^}]*(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
SOURCEMAP_ENABLED_PATTERN = re.compile(
    r"sourcemap\s*:\s*(?:true|['\"]inline['\"])",
    re.IGNORECASE,
)
EMBEDDED_TRUE_PATTERN = re.compile(
    r"embedded\s*:\s*true",
    re.IGNORECASE,
)
HANDLE_HTTP_ERROR_IGNORE_PATTERN = re.compile(
    r"handleHttpError\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
PRERENDER_HANDLE_MISSING_IGNORE_PATTERN = re.compile(
    r"handleMissingId\s*:\s*['\"]ignore['\"]",
    re.IGNORECASE,
)
SERVICE_WORKER_REGISTER_PATTERN = re.compile(
    r"serviceWorker\s*:\s*\{[^}]*register\s*:\s*true",
    re.IGNORECASE | re.DOTALL,
)
VERSION_POLL_INTERVAL_PATTERN = re.compile(
    r"pollInterval\s*:\s*\d+",
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
    has_adapter: bool = False
    has_csrf: bool = False
    has_csp: bool = False
    has_env: bool = False
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


def _is_sveltekit_file(path: Path) -> bool:
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
                "@sveltejs/kit" in deps or "svelte" in deps
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class SvelteKitAnalyzer:
    """Audit SvelteKit configuration for security and production risks.

    Scans svelte.config.* files for hardcoded secrets, disabled CSRF origin
    checks, permissive CSP, exposed dev servers, adapter credential leaks,
    internal proxy targets, and production sourcemaps.
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
                if path.is_file() and path not in found and _is_sveltekit_file(path):
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

        for section in ("kit", "vite", "adapter", "csrf", "csp", "env"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "kit":
                    info.has_kit = True
                elif section == "vite":
                    info.has_vite = True
                elif section == "adapter":
                    info.has_adapter = True
                elif section == "csrf":
                    info.has_csrf = True
                elif section == "csp":
                    info.has_csp = True
                elif section == "env":
                    info.has_env = True

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
            (ADAPTER_SECRET_PATTERN, "adapter_secret", "high",
             "secret in adapter config — use environment variables at deploy time"),
            (KIT_ENV_SECRET_PATTERN, "kit_env_secret", "high",
             "secret in kit.env — use $env/static/private or runtime env vars"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy/redirect to internal IP — SSRF risk in dev and production"),
            (CSRF_CHECK_ORIGIN_FALSE_PATTERN, "csrf_origin_disabled", "high",
             "kit.csrf.checkOrigin disabled — CSRF protection weakened"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost in dev"),
            (CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "CSP disabled or set to unsafe — XSS protection weakened"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access dev server or APIs"),
            (CSRF_TRUSTED_WILDCARD_PATTERN, "csrf_trusted_wildcard", "medium",
             "kit.csrf.trustedOrigins includes wildcard — any origin may bypass CSRF"),
            (FS_ALLOW_PERMISSIVE_PATTERN, "fs_allow_permissive", "medium",
             "vite.server.fs.allow is permissive — dev server may read sensitive paths"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (SOURCEMAP_ENABLED_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (EMBEDDED_TRUE_PATTERN, "embedded_mode", "medium",
             "embedded mode enabled — verify this is intentional for production"),
            (SERVICE_WORKER_REGISTER_PATTERN, "service_worker_register", "medium",
             "service worker auto-registration enabled — verify cache and scope policies"),
            (HANDLE_HTTP_ERROR_IGNORE_PATTERN, "http_error_ignored", "low",
             "handleHttpError set to ignore — errors may be silently swallowed"),
            (PRERENDER_HANDLE_MISSING_IGNORE_PATTERN, "prerender_missing_ignored", "low",
             "handleMissingId set to ignore — broken links may go unnoticed"),
            (CSP_REPORT_ONLY_FALSE_PATTERN, "csp_enforced", "low",
             "CSP reportOnly disabled — verify policy before enforcing in production"),
            (VERSION_POLL_INTERVAL_PATTERN, "version_poll_enabled", "low",
             "version polling enabled — may increase server load"),
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
import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csrf: {
      checkOrigin: true,
    },
    csp: {
      mode: 'auto',
      directives: {
        'default-src': ['self'],
        'script-src': ['self'],
        'style-src': ['self', 'unsafe-inline'],
      },
    },
    env: {
      // Use $env/static/private for secrets — never hardcode here
      publicPrefix: 'PUBLIC_',
    },
    paths: {
      relative: false,
    },
    prerender: {
      handleMissingId: 'warn',
    },
  },
};

export default config;
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
