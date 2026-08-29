"""QwikAnalyzer — audit Qwik City configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

QWIK_CONFIG_NAMES = (
    "qwik.config.ts",
    "qwik.config.js",
    "qwik.config.mjs",
    "qwik.config.cjs",
    "qwik-city.config.ts",
    "qwik-city.config.js",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|accessToken)\s*[=:]\s*"
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
    r"(?:host|devServerHost)\s*:\s*(?:true|['\"]0\.0\.0\.0['\"]|['\"]::['\"])",
    re.IGNORECASE,
)
ORIGIN_WILDCARD_PATTERN = re.compile(
    r"(?:origin|allowedOrigins)\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
CHECK_ORIGIN_FALSE_PATTERN = re.compile(
    r"(?:checkOrigin|verifyOrigin)\s*:\s*false",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"(?:csrfProtection|csrf)\s*:\s*false",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|proxy|destination|url|rewrite)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
TLS_REJECT_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
SOURCEMAP_ENABLED_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap|sourceMaps)\s*[=:]\s*(?:true|['\"]inline['\"]|['\"]hidden['\"])",
    re.IGNORECASE,
)
CORS_OPEN_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|cors)\s*:\s*(?:['\"]\*['\"]|true)",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET|ACCESS[_-]?TOKEN)\s*:\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
ADAPTER_CREDENTIAL_PATTERN = re.compile(
    r"(?:accessKeyId|secretAccessKey|apiToken|authToken|privateKey|accountId)\s*:\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PREFETCH_ALL_PATTERN = re.compile(
    r"(?:prefetchAll|prefetchStrategy)\s*:\s*['\"]all['\"]",
    re.IGNORECASE,
)
SERVICE_WORKER_INSECURE_PATTERN = re.compile(
    r"(?:serviceWorker|sw)\s*:\s*\{[^}]*scope\s*:\s*['\"]/['\"]",
    re.IGNORECASE | re.DOTALL,
)
TRUSTED_ORIGINS_WILDCARD_PATTERN = re.compile(
    r"trustedOrigins\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
BASE_PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:basePathname|base)\s*:\s*['\"][^'\"]*\.\.[^'\"]*['\"]",
    re.IGNORECASE,
)
DEVTOOLS_ENABLED_PATTERN = re.compile(
    r"(?:devtools|devTools)\s*:\s*(?:true|\{[^}]*enabled\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
INLINE_SCRIPT_UNSAFE_PATTERN = re.compile(
    r"dangerouslySetInnerHTML|innerHTML\s*=",
    re.IGNORECASE,
)


@dataclass
class QwikFinding:
    """A security or best-practice issue in a Qwik configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class QwikInfo:
    """Parsed metadata about a Qwik configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_adapter: bool = False
    has_server: bool = False
    has_vite: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class QwikStats:
    """Aggregate Qwik analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_qwik_file(path: Path) -> bool:
    name = path.name
    return name in QWIK_CONFIG_NAMES or any(
        name.startswith(prefix)
        for prefix in ("qwik.config.", "qwik-city.config.")
    )


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_qwik_project(root: Path) -> bool:
    if any((root / name).exists() for name in QWIK_CONFIG_NAMES):
        return True
    for pattern in ("qwik.config.*", "qwik-city.config.*"):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(
                key.startswith("@builder.io/qwik") or key == "qwik" for key in deps
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class QwikAnalyzer:
    """Audit Qwik City configuration for security and production risks.

    Scans qwik.config.* and qwik-city.config.* for hardcoded secrets,
    disabled CSRF/origin checks, path traversal in base paths, internal
    proxy targets, exposed dev servers, and production sourcemaps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[QwikFinding] | None = None
        self._stats: QwikStats | None = None
        self._infos: list[QwikInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Qwik configuration paths found in the project."""
        found: list[Path] = []
        for name in QWIK_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("qwik.config.*", "qwik-city.config.*"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_qwik_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[QwikFinding],
        info: QwikInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("adapter", "server", "vite", "devServer", "preview", "origin", "csrf"):
            if section in stripped and (":" in stripped or "[" in stripped):
                if section not in info.sections:
                    info.sections.append(section)
                if section == "adapter":
                    info.has_adapter = True
                elif section == "server":
                    info.has_server = True
                elif section == "vite":
                    info.has_vite = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Qwik config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Qwik config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Qwik config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Qwik config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Qwik config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Qwik config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in config — use runtime environment variables"),
            (ADAPTER_CREDENTIAL_PATTERN, "adapter_credential", "high",
             "adapter credential in Qwik config — use environment variables"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy/redirect to internal IP — SSRF risk in dev and production"),
            (BASE_PATH_TRAVERSAL_PATTERN, "path_traversal", "high",
             "path traversal in basePathname — restrict to project directory"),
            (CHECK_ORIGIN_FALSE_PATTERN, "origin_check_disabled", "high",
             "origin verification disabled — CSRF and DNS rebinding risk"),
            (CSRF_DISABLED_PATTERN, "csrf_disabled", "high",
             "CSRF protection disabled — enable csrfProtection in server config"),
            (ORIGIN_WILDCARD_PATTERN, "origin_wildcard", "high",
             "wildcard origin allowed — restrict to trusted domains"),
            (TRUSTED_ORIGINS_WILDCARD_PATTERN, "trusted_origins_wildcard", "high",
             "trustedOrigins includes wildcard — restrict to known hosts"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost"),
            (TLS_REJECT_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled — TLS verification bypassed"),
            (SOURCEMAP_ENABLED_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access APIs"),
            (INLINE_SCRIPT_UNSAFE_PATTERN, "unsafe_inner_html", "medium",
             "dangerouslySetInnerHTML/innerHTML — XSS risk if content is untrusted"),
            (PREFETCH_ALL_PATTERN, "prefetch_all", "medium",
             "prefetchAll strategy — may prefetch sensitive routes"),
            (SERVICE_WORKER_INSECURE_PATTERN, "service_worker_scope", "medium",
             "service worker scope at root — verify cache isolation"),
            (DEVTOOLS_ENABLED_PATTERN, "devtools_enabled", "low",
             "devtools enabled — verify disabled in production builds"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    QwikFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[QwikFinding], QwikInfo]:
        findings: list[QwikFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, QwikInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = QwikInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[QwikFinding]:
        """Scan Qwik configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[QwikFinding] = []
        infos: list[QwikInfo] = []
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
        self._stats = QwikStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> QwikStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[QwikInfo]:
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
        """Scaffold a hardened qwik.config.ts template."""
        return """\
// Generated by DevAI QwikAnalyzer
import { defineConfig } from '@builder.io/qwik-city/vite';
import { qwikVite } from '@builder.io/qwik/optimizer';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig(() => ({
  plugins: [qwikVite(), tsconfigPaths()],
  server: {
    host: 'localhost',
    strictPort: true,
    origin: 'https://localhost:5173',
  },
  preview: {
    host: 'localhost',
    strictPort: true,
  },
  build: {
    sourcemap: false,
  },
}));
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Qwik: no configuration files found"
        return (
            f"Qwik: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Qwik configuration analysis:",
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
