"""WebpackAnalyzer — audit Webpack build configs for security and dev-server risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

WEBPACK_CONFIG_NAMES = (
    "webpack.config.js",
    "webpack.config.ts",
    "webpack.config.mts",
    "webpack.config.mjs",
    "webpack.config.cjs",
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
DEVTOOL_SOURCEMAP_PATTERN = re.compile(
    r"devtool\s*:\s*['\"]?(?:source-map|inline-source-map|hidden-source-map|"
    r"nosources-source-map|eval-source-map|cheap-source-map|cheap-module-source-map)['\"]?",
    re.IGNORECASE,
)
DEVTOOL_EVAL_PATTERN = re.compile(
    r"devtool\s*:\s*['\"]?eval['\"]?",
    re.IGNORECASE,
)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:host|devServer\s*:\s*\{[^}]*host)\s*:\s*(?:true|['\"]0\.0\.0\.0['\"]|['\"]::['\"])",
    re.IGNORECASE | re.DOTALL,
)
ALLOWED_HOSTS_ALL_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:['\"]all['\"]|'all'|\"all\")",
    re.IGNORECASE,
)
DISABLE_HOST_CHECK_PATTERN = re.compile(
    r"disableHostCheck\s*:\s*true",
    re.IGNORECASE,
)
CORS_OPEN_PATTERN = re.compile(
    r"(?:headers\s*:\s*\{[^}]*['\"]Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*['\"]|"
    r"cors\s*:\s*(?:true|['\"]true['\"]))",
    re.IGNORECASE | re.DOTALL,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|pathRewrite)\s*:\s*['\"]https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
DEFINE_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*JSON\.stringify\(['\"][^'\"${}]+['\"]\)|"
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
WRITE_TO_DISK_TRUE_PATTERN = re.compile(
    r"writeToDisk\s*:\s*true",
    re.IGNORECASE,
)
PUBLIC_PATH_ABSOLUTE_PATTERN = re.compile(
    r"publicPath\s*:\s*['\"]https?://[^'\"]+['\"]",
    re.IGNORECASE,
)
NODE_POLYFILL_ALL_PATTERN = re.compile(
    r"fallback\s*:\s*\{[^}]*['\"]?\*['\"]?\s*:",
    re.IGNORECASE,
)
EXPOSE_LOADER_PATTERN = re.compile(
    r"expose-loader|ExposeWebpackPlugin",
    re.IGNORECASE,
)
WEBPACK_DEV_SERVER_UNSAFE_PATTERN = re.compile(
    r"devServer\s*:\s*\{[^}]*(?:static\s*:\s*\{[^}]*directory\s*:\s*['\"]\.\.['\"]|"
    r"watchFiles\s*:\s*\[[^\]]*(?:\.\./|['\"]\*['\"]))",
    re.IGNORECASE | re.DOTALL,
)
MINIMIZE_FALSE_PATTERN = re.compile(
    r"minimize\s*:\s*false",
    re.IGNORECASE,
)
MODE_DEVELOPMENT_PATTERN = re.compile(
    r"mode\s*:\s*['\"]development['\"]",
    re.IGNORECASE,
)


@dataclass
class WebpackFinding:
    """A security or best-practice issue in a Webpack configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class WebpackInfo:
    """Parsed metadata about a Webpack configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_dev_server: bool = False
    has_optimization: bool = False
    has_plugins: bool = False
    has_proxy: bool = False
    mode: str | None = None
    plugins: list[str] = field(default_factory=list)


@dataclass
class WebpackStats:
    """Aggregate Webpack analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_webpack_file(path: Path) -> bool:
    name = path.name.lower()
    if name in WEBPACK_CONFIG_NAMES:
        return True
    if name.startswith("webpack.") and name.endswith((".js", ".ts", ".mjs", ".cjs", ".mts")):
        return True
    if name.startswith("webpack.config.") and name.endswith((".js", ".ts", ".mjs", ".cjs", ".mts")):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


class WebpackAnalyzer:
    """Audit Webpack build configuration for security and dev-server risks.

    Scans webpack.config.* files for hardcoded secrets, exposed dev servers,
    permissive allowedHosts, open CORS, internal proxy targets, production
    sourcemaps, disabled minification, and dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[WebpackFinding] | None = None
        self._stats: WebpackStats | None = None
        self._infos: list[WebpackInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Webpack configuration paths found in the project."""
        found: list[Path] = []
        for name in WEBPACK_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("webpack.config.*", "webpack.*.js", "webpack.*.ts"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_webpack_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[WebpackFinding],
        info: WebpackInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if "devServer" in stripped and ":" in stripped:
            info.has_dev_server = True
        if "optimization" in stripped and ":" in stripped:
            info.has_optimization = True
        if "plugins" in stripped and ":" in stripped:
            info.has_plugins = True
        if "proxy" in stripped and ":" in stripped:
            info.has_proxy = True

        mode_match = re.search(r"mode\s*:\s*['\"](\w+)['\"]", stripped, re.IGNORECASE)
        if mode_match:
            info.mode = mode_match.group(1).lower()

        plugin_match = re.search(r"(?:new\s+)(\w+)(?:\s*\()", stripped)
        if plugin_match:
            plugin_name = plugin_match.group(1)
            if plugin_name not in info.plugins:
                info.plugins.append(plugin_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Webpack config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Webpack config — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Webpack config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_ENV_PATTERN.search(line):
            findings.append(
                WebpackFinding(
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
                WebpackFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Webpack config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous shell command in Webpack config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval() in Webpack config — avoid dynamic code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEFINE_SECRET_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="define_secret",
                    severity="high",
                    message="secret value in DefinePlugin or define block — use runtime env injection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROXY_INTERNAL_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="proxy_internal",
                    severity="high",
                    message="proxy target points to internal/private network — SSRF risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXPOSE_LOADER_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="expose_loader",
                    severity="high",
                    message="expose-loader exposes module globals — may leak internal APIs to window",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HOST_EXPOSED_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="host_exposed",
                    severity="medium",
                    message="dev server bound to all interfaces — restrict to localhost in development",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOWED_HOSTS_ALL_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="allowed_hosts_all",
                    severity="medium",
                    message="allowedHosts set to 'all' — enables DNS rebinding attacks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLE_HOST_CHECK_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="disable_host_check",
                    severity="medium",
                    message="disableHostCheck enabled — allows DNS rebinding attacks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CORS_OPEN_PATTERN.search(line):
            findings.append(
                WebpackFinding(
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
                WebpackFinding(
                    kind="reject_unauthorized_false",
                    severity="medium",
                    message="rejectUnauthorized disabled — TLS verification bypassed for dev server",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEVTOOL_SOURCEMAP_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="sourcemap_enabled",
                    severity="medium",
                    message="source maps enabled via devtool — may expose source in production bundles",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEVTOOL_EVAL_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="devtool_eval",
                    severity="medium",
                    message="devtool set to eval — may execute untrusted code during development",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MINIMIZE_FALSE_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="minimize_disabled",
                    severity="medium",
                    message="minification disabled — production bundles may be larger and easier to reverse",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WEBPACK_DEV_SERVER_UNSAFE_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="devserver_unsafe_static",
                    severity="medium",
                    message="devServer serves parent directories or wildcard paths — restrict static roots",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NODE_POLYFILL_ALL_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="polyfill_wildcard",
                    severity="medium",
                    message="resolve.fallback uses wildcard polyfills — may bundle untrusted shims",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WRITE_TO_DISK_TRUE_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="write_to_disk",
                    severity="low",
                    message="writeToDisk enabled — dev middleware writes bundles to disk unexpectedly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PUBLIC_PATH_ABSOLUTE_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="public_path_absolute",
                    severity="low",
                    message="absolute publicPath URL — verify CDN origin and cache headers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MODE_DEVELOPMENT_PATTERN.search(line):
            findings.append(
                WebpackFinding(
                    kind="mode_development",
                    severity="low",
                    message="mode set to development — ensure production builds use mode: 'production'",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[WebpackFinding], WebpackInfo]:
        findings: list[WebpackFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, WebpackInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = WebpackInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[WebpackFinding]:
        """Scan Webpack configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[WebpackFinding] = []
        infos: list[WebpackInfo] = []
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
        self._stats = WebpackStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> WebpackStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[WebpackInfo]:
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
        """Scaffold a hardened webpack.config.js template."""
        return """\
// Generated by DevAI WebpackAnalyzer
const path = require('path');

module.exports = {
  mode: 'production',
  devtool: false,
  output: {
    publicPath: '/',
    path: path.resolve(__dirname, 'dist'),
  },
  devServer: {
    host: 'localhost',
    allowedHosts: ['localhost'],
    static: { directory: path.join(__dirname, 'public') },
    client: { overlay: true },
  },
  optimization: {
    minimize: true,
  },
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Webpack: no configuration files found"
        return (
            f"Webpack: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Webpack configuration analysis:",
            f"  config files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            flags = []
            if info.has_dev_server:
                flags.append("devServer")
            if info.has_optimization:
                flags.append("optimization")
            if info.has_plugins:
                flags.append("plugins")
            if info.has_proxy:
                flags.append("proxy")
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"mode={info.mode or 'unset'}, sections={','.join(flags) or 'none'}, "
                f"plugins={len(info.plugins)}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
