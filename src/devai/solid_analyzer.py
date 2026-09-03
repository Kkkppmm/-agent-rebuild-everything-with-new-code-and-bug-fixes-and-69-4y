"""SolidAnalyzer — audit SolidJS and SolidStart configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

APP_CONFIG_NAMES = (
    "app.config.ts",
    "app.config.js",
    "app.config.mjs",
)
SOLID_CONFIG_NAMES = (
    "solid.config.ts",
    "solid.config.js",
    "solid.config.mjs",
)
VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.mts",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret)\s*[=:]\s*"
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
ALLOWED_HOSTS_ALL_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:['\"]all['\"]|\[['\"]all['\"]\])",
    re.IGNORECASE,
)
ORIGIN_WILDCARD_PATTERN = re.compile(
    r"(?:allowedOrigins|origin)\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|rewrite|destination|proxy)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
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
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
SOURCEMAP_TRUE_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap)\s*:\s*(?:true|['\"]inline['\"]|['\"]hidden['\"])",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET|SESSION[_-]?SECRET)"
    r"\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
ADAPTER_SECRET_PATTERN = re.compile(
    r"(?:accessKeyId|secretAccessKey|apiToken|authToken|privateKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
SSR_DISABLED_PATTERN = re.compile(
    r"ssr\s*:\s*false",
    re.IGNORECASE,
)
CSP_DISABLED_PATTERN = re.compile(
    r"csp\s*:\s*false",
    re.IGNORECASE,
)
MIDDLEWARE_SECRET_PATTERN = re.compile(
    r"(?:middleware|session)\s*:\s*\{[^}]*(?:secret|password)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
VINXI_PUBLIC_DIR_PATTERN = re.compile(
    r"publicDir\s*:\s*['\"]\.\./",
    re.IGNORECASE,
)
SOLID_VITE_PLUGIN_PATTERN = re.compile(
    r"(?:vite-plugin-solid|solid\s*\(|from\s+['\"]vite-plugin-solid['\"])",
    re.IGNORECASE,
)
SOLID_START_CONFIG_PATTERN = re.compile(
    r"(?:@solidjs/start|defineConfig\s*\(\s*\{[^}]*server)",
    re.IGNORECASE,
)
SOLID_START_IMPORT_PATTERN = re.compile(
    r"from\s+['\"]@solidjs/start/config['\"]",
    re.IGNORECASE,
)
PRESET_NODE_EXPOSED_PATTERN = re.compile(
    r"preset\s*:\s*['\"]node['\"]",
    re.IGNORECASE,
)
TRUST_PROXY_ALL_PATTERN = re.compile(
    r"trustProxy\s*:\s*(?:true|['\"]all['\"])",
    re.IGNORECASE,
)


@dataclass
class SolidFinding:
    """A security or best-practice issue in a SolidJS configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class SolidInfo:
    """Parsed metadata about a SolidJS configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_solid_vite: bool = False
    has_solid_start: bool = False
    has_server: bool = False
    has_ssr: bool = True
    sections: list[str] = field(default_factory=list)


@dataclass
class SolidStats:
    """Aggregate SolidJS analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_app_config_file(path: Path) -> bool:
    return path.name in APP_CONFIG_NAMES or path.name.startswith("app.config.")


def _is_solid_config_file(path: Path) -> bool:
    return path.name in SOLID_CONFIG_NAMES or path.name.startswith("solid.config.")


def _is_vite_solid_file(path: Path, text: str | None = None) -> bool:
    if path.name not in VITE_CONFIG_NAMES and not path.name.startswith("vite.config."):
        return False
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(SOLID_VITE_PLUGIN_PATTERN.search(text))


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_solid_project(root: Path) -> bool:
    if any((root / name).exists() for name in APP_CONFIG_NAMES):
        return True
    for pattern in ("app.config.*", "solid.config.*"):
        if any(root.glob(pattern)):
            return True
    for pattern in VITE_CONFIG_NAMES:
        path = root / pattern
        if path.is_file() and _is_vite_solid_file(path):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(
                k in deps
                for k in (
                    "solid-js",
                    "vite-plugin-solid",
                    "@solidjs/start",
                    "@solidjs/router",
                )
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class SolidAnalyzer:
    """Audit SolidJS and SolidStart configuration for security and production risks.

    Scans app.config.*, solid.config.*, and vite.config.* (with vite-plugin-solid)
    for hardcoded secrets, exposed dev servers, permissive allowedHosts, internal
    proxies, disabled CSP, and session secret leaks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SolidFinding] | None = None
        self._stats: SolidStats | None = None
        self._infos: list[SolidInfo] | None = None

    def configs(self) -> list[Path]:
        """Return SolidJS configuration paths found in the project."""
        found: list[Path] = []
        for name in APP_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("app.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_app_config_file(path):
                    found.append(path)
        for name in SOLID_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and path not in found:
                found.append(path)
        for pattern in ("solid.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_solid_config_file(path):
                    found.append(path)
        for name in VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and path not in found and _is_vite_solid_file(path):
                found.append(path)
        for pattern in ("vite.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_vite_solid_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SolidFinding],
        info: SolidInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if SOLID_VITE_PLUGIN_PATTERN.search(line):
            info.has_solid_vite = True
            if "solid" not in info.sections:
                info.sections.append("solid")

        if SOLID_START_IMPORT_PATTERN.search(line) or SOLID_START_CONFIG_PATTERN.search(line):
            info.has_solid_start = True
            if "solidstart" not in info.sections:
                info.sections.append("solidstart")

        for section in ("server", "preview", "build", "ssr", "middleware", "vinxi"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section in ("server", "preview", "vinxi"):
                    info.has_server = True
                if section == "ssr" and "false" in stripped.lower():
                    info.has_ssr = False

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in SolidJS config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in SolidJS config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in SolidJS config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in SolidJS config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in SolidJS config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in SolidJS config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (ADAPTER_SECRET_PATTERN, "adapter_secret", "high",
             "credential in adapter config — use environment variables or secret stores"),
            (MIDDLEWARE_SECRET_PATTERN, "middleware_secret", "high",
             "session/middleware secret hardcoded — use environment variables"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy target to internal IP — SSRF risk in dev server"),
            (VINXI_PUBLIC_DIR_PATTERN, "public_dir_parent", "high",
             "publicDir points outside project root — may expose sensitive files"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "server host exposed to all interfaces — restrict to localhost in dev"),
            (ALLOWED_HOSTS_ALL_PATTERN, "allowed_hosts_all", "medium",
             "allowedHosts: 'all' — DNS rebinding attacks possible against dev server"),
            (ORIGIN_WILDCARD_PATTERN, "origin_wildcard", "medium",
             "allowedOrigins includes * — any origin may access server endpoints"),
            (FS_ALLOW_PERMISSIVE_PATTERN, "fs_allow_permissive", "medium",
             "vite.server.fs.allow is permissive — dev server may read sensitive paths"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "vite.server.cors enabled without restrictions — any origin may access dev server"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (SOURCEMAP_TRUE_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (SSR_DISABLED_PATTERN, "ssr_disabled", "medium",
             "SSR disabled — verify SPA mode is intentional for this route tree"),
            (CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "CSP disabled — content security policy should be enabled in production"),
            (PRESET_NODE_EXPOSED_PATTERN, "node_preset", "low",
             "node preset selected — verify server hardening for production deployments"),
            (TRUST_PROXY_ALL_PATTERN, "trust_proxy_all", "low",
             "trustProxy enabled broadly — verify reverse proxy configuration"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    SolidFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[SolidFinding], SolidInfo]:
        findings: list[SolidFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, SolidInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = SolidInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[SolidFinding]:
        """Scan SolidJS configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SolidFinding] = []
        infos: list[SolidInfo] = []
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
        self._stats = SolidStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SolidStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SolidInfo]:
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
        """Scaffold a hardened app.config.ts template for SolidStart."""
        return """\
// Generated by DevAI SolidAnalyzer
import { defineConfig } from '@solidjs/start/config';

export default defineConfig({
  server: {
    preset: 'node-server',
    host: '127.0.0.1',
    port: 3000,
    strictPort: true,
  },
  ssr: true,
  middleware: './src/middleware.ts',
  vite: {
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      fs: { allow: ['.'] },
      cors: false,
    },
    build: {
      sourcemap: false,
    },
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "SolidJS: no configuration files found"
        return (
            f"SolidJS: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "SolidJS configuration analysis:",
            f"  config files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"sections={','.join(info.sections) or 'none'}, ssr={info.has_ssr}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
