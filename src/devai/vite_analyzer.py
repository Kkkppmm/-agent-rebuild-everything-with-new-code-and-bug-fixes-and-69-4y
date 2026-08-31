"""ViteAnalyzer — audit Vite build configs for security and dev-server risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mts",
    "vite.config.mjs",
    "vite.config.cjs",
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
SOURCEMAP_TRUE_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap)\s*:\s*(?:true|['\"]inline['\"]|['\"]hidden['\"])",
    re.IGNORECASE,
)
HOST_EXPOSED_PATTERN = re.compile(
    r"host\s*:\s*(?:true|['\"]0\.0\.0\.0['\"]|['\"]::['\"])",
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
    r"(?:target|rewrite)\s*:\s*['\"]https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
MINIFY_FALSE_PATTERN = re.compile(
    r"minify\s*:\s*false",
    re.IGNORECASE,
)
SSR_NO_EXTERNAL_ALL_PATTERN = re.compile(
    r"noExternal\s*:\s*(?:true|['\"]true['\"]|\[\s*['\"]\*['\"]\s*\])",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
DEFINE_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
ENV_PREFIX_BROAD_PATTERN = re.compile(
    r"envPrefix\s*:\s*['\"]?['\"]",
    re.IGNORECASE,
)
OPEN_BROWSER_PATTERN = re.compile(
    r"open\s*:\s*true",
    re.IGNORECASE,
)
STRICT_PORT_FALSE_PATTERN = re.compile(
    r"strictPort\s*:\s*false",
    re.IGNORECASE,
)
INLINE_ALL_DEPS_PATTERN = re.compile(
    r"optimizeDeps\s*:\s*\{[^}]*include\s*:\s*\[\s*['\"]\*['\"]\s*\]",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class ViteFinding:
    """A security or best-practice issue in a Vite configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ViteInfo:
    """Parsed metadata about a Vite configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_server: bool = False
    has_build: bool = False
    has_proxy: bool = False
    has_define: bool = False
    plugins: list[str] = field(default_factory=list)


@dataclass
class ViteStats:
    """Aggregate Vite analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vite_file(path: Path) -> bool:
    return path.name in VITE_CONFIG_NAMES or path.name.startswith("vite.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    if name == "package.json":
        return "package"
    return "unknown"


def _looks_like_vite_project(root: Path) -> bool:
    if any((root / name).exists() for name in VITE_CONFIG_NAMES):
        return True
    for pattern in ("vite.config.*",):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            if isinstance(deps, dict) and "vite" in deps:
                return True
            if isinstance(dev_deps, dict) and "vite" in dev_deps:
                return True
        except json.JSONDecodeError:
            pass
    return False


class ViteAnalyzer:
    """Audit Vite build configuration for security and dev-server risks.

    Scans vite.config.* files for hardcoded secrets, exposed dev servers,
    permissive fs.allow, open CORS, internal proxy targets, production
    sourcemaps, disabled minification, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ViteFinding] | None = None
        self._stats: ViteStats | None = None
        self._infos: list[ViteInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Vite configuration paths found in the project."""
        found: list[Path] = []
        for name in VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("vite.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_vite_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ViteFinding],
        info: ViteInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if "server" in stripped and ":" in stripped:
            info.has_server = True
        if "build" in stripped and ":" in stripped:
            info.has_build = True
        if "proxy" in stripped and ":" in stripped:
            info.has_proxy = True
        if "define" in stripped and ":" in stripped:
            info.has_define = True

        plugin_match = re.search(r"(?:from\s+['\"])([^'\"]+)(?:['\"])", stripped)
        if plugin_match and "plugin" in stripped.lower():
            plugin_name = plugin_match.group(1)
            if plugin_name not in info.plugins:
                info.plugins.append(plugin_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Vite config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Vite config — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Vite config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_ENV_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="tls_verification_disabled",
                    severity="high",
                    message="TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Vite config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous shell command in Vite config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval() in Vite config — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEFINE_SECRET_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="define_secret",
                    severity="high",
                    message="secret value in define block — use runtime env injection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROXY_INTERNAL_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="proxy_internal",
                    severity="high",
                    message="proxy target points to internal/private network — SSRF risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HOST_EXPOSED_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="host_exposed",
                    severity="medium",
                    message="dev server bound to all interfaces — restrict to localhost in development",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FS_ALLOW_PERMISSIVE_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="fs_allow_permissive",
                    severity="medium",
                    message="permissive fs.allow — restrict file system access to project root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CORS_OPEN_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="cors_open",
                    severity="medium",
                    message="CORS enabled without origin restrictions — restrict allowed origins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REJECT_UNAUTHORIZED_FALSE_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="reject_unauthorized_false",
                    severity="medium",
                    message="rejectUnauthorized disabled — TLS verification bypassed for dev server",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SOURCEMAP_TRUE_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="sourcemap_enabled",
                    severity="medium",
                    message="source maps enabled — may expose source in production bundles",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MINIFY_FALSE_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="minify_disabled",
                    severity="medium",
                    message="minification disabled — production bundles may be larger and easier to reverse",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SSR_NO_EXTERNAL_ALL_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="ssr_no_external_all",
                    severity="medium",
                    message="ssr.noExternal set to all — may bundle server-only dependencies into client",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INLINE_ALL_DEPS_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="inline_all_deps",
                    severity="medium",
                    message="optimizeDeps.include set to * — may pre-bundle untrusted dependencies",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_PREFIX_BROAD_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="env_prefix_broad",
                    severity="low",
                    message="empty envPrefix — all env vars may be exposed to client bundle",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OPEN_BROWSER_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="open_browser",
                    severity="low",
                    message="auto-open browser enabled — may be unexpected in CI or remote dev",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_PORT_FALSE_PATTERN.search(line):
            findings.append(
                ViteFinding(
                    kind="strict_port_false",
                    severity="low",
                    message="strictPort disabled — dev server may silently bind to alternate port",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[ViteFinding], ViteInfo]:
        findings: list[ViteFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ViteInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = ViteInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[ViteFinding]:
        """Scan Vite configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ViteFinding] = []
        infos: list[ViteInfo] = []
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
        self._stats = ViteStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ViteStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ViteInfo]:
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
        """Scaffold a hardened vite.config.ts template."""
        return """\
// Generated by DevAI ViteAnalyzer
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'localhost',
    strictPort: true,
    cors: { origin: 'http://localhost:5173' },
    fs: { allow: ['.'] },
  },
  build: {
    sourcemap: false,
    minify: 'esbuild',
  },
  envPrefix: 'VITE_',
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Vite: no configuration files found"
        return (
            f"Vite: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Vite configuration analysis:",
            f"  config files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            flags = []
            if info.has_server:
                flags.append("server")
            if info.has_build:
                flags.append("build")
            if info.has_proxy:
                flags.append("proxy")
            if info.has_define:
                flags.append("define")
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"sections={','.join(flags) or 'none'}, plugins={len(info.plugins)}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
