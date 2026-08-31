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
)
VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.mts",
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
ORIGIN_WILDCARD_PATTERN = re.compile(
    r"(?:allowedOrigins|origin)\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
CHECK_ORIGIN_FALSE_PATTERN = re.compile(
    r"checkOrigin\s*:\s*false",
    re.IGNORECASE,
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
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
ADAPTER_SECRET_PATTERN = re.compile(
    r"(?:accessKeyId|secretAccessKey|apiToken|authToken|privateKey)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
TRAILING_SLASH_FALSE_PATTERN = re.compile(
    r"trailingSlash\s*:\s*false",
    re.IGNORECASE,
)
BASE_PATHABSOLUTE_PATTERN = re.compile(
    r"basePathname\s*:\s*['\"]https?://",
    re.IGNORECASE,
)
QWIK_CITY_PLUGIN_PATTERN = re.compile(r"qwikCity\s*\(", re.IGNORECASE)
QWIK_VITE_PLUGIN_PATTERN = re.compile(r"qwikVite\s*\(", re.IGNORECASE)


@dataclass
class QwikFinding:
    """A security or best-practice issue in a Qwik City configuration file."""

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
    """Parsed metadata about a Qwik City configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_qwik_city: bool = False
    has_qwik_vite: bool = False
    has_server: bool = False
    has_adapter: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class QwikStats:
    """Aggregate Qwik City analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_qwik_config_file(path: Path) -> bool:
    return path.name in QWIK_CONFIG_NAMES or path.name.startswith("qwik.config.")


def _is_vite_qwik_file(path: Path, text: str | None = None) -> bool:
    if path.name not in VITE_CONFIG_NAMES and not path.name.startswith("vite.config."):
        return False
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(QWIK_CITY_PLUGIN_PATTERN.search(text) or QWIK_VITE_PLUGIN_PATTERN.search(text))


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
    for pattern in ("qwik.config.*",):
        if any(root.glob(pattern)):
            return True
    for pattern in VITE_CONFIG_NAMES:
        path = root / pattern
        if path.is_file() and _is_vite_qwik_file(path):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(
                k in deps for k in ("@builder.io/qwik", "@builder.io/qwik-city")
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class QwikAnalyzer:
    """Audit Qwik City configuration for security and production risks.

    Scans qwik.config.* and vite.config.* (with Qwik plugins) for hardcoded
    secrets, exposed dev servers, disabled origin checks, internal proxies,
    permissive filesystem access, and adapter credential leaks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[QwikFinding] | None = None
        self._stats: QwikStats | None = None
        self._infos: list[QwikInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Qwik City configuration paths found in the project."""
        found: list[Path] = []
        for name in QWIK_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("qwik.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_qwik_config_file(path):
                    found.append(path)
        for name in VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and path not in found and _is_vite_qwik_file(path):
                found.append(path)
        for pattern in ("vite.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_vite_qwik_file(path):
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

        if QWIK_CITY_PLUGIN_PATTERN.search(line):
            info.has_qwik_city = True
            if "qwikCity" not in info.sections:
                info.sections.append("qwikCity")
        if QWIK_VITE_PLUGIN_PATTERN.search(line):
            info.has_qwik_vite = True
            if "qwikVite" not in info.sections:
                info.sections.append("qwikVite")

        for section in ("server", "adapter", "preview", "build"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section in ("server", "preview"):
                    info.has_server = True
                if section == "adapter":
                    info.has_adapter = True

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
             "secret value in env block — use runtime environment variables"),
            (ADAPTER_SECRET_PATTERN, "adapter_secret", "high",
             "credential in adapter config — use environment variables or secret stores"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy target to internal IP — SSRF risk in dev server"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "server host exposed to all interfaces — restrict to localhost in dev"),
            (CHECK_ORIGIN_FALSE_PATTERN, "check_origin_disabled", "medium",
             "checkOrigin disabled — CSRF protection weakened for server endpoints"),
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
            (BASE_PATHABSOLUTE_PATTERN, "base_path_absolute", "low",
             "basePathname uses absolute URL — verify canonical routing intent"),
            (TRAILING_SLASH_FALSE_PATTERN, "trailing_slash_false", "low",
             "trailingSlash disabled — may cause redirect loops behind proxies"),
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
        """Scan Qwik City configuration files and return findings."""
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
        """Scaffold a hardened vite.config.ts template for Qwik City."""
        return """\
// Generated by DevAI QwikAnalyzer
import { defineConfig } from 'vite';
import { qwikVite } from '@builder.io/qwik/optimizer';
import { qwikCity } from '@builder.io/qwik-city/vite';

export default defineConfig({
  plugins: [
    qwikCity({
      trailingSlash: true,
    }),
    qwikVite(),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    fs: { allow: ['.'] },
    cors: false,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  build: {
    sourcemap: false,
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Qwik City: no configuration files found"
        return (
            f"Qwik City: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Qwik City configuration analysis:",
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
