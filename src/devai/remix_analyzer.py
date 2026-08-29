"""RemixAnalyzer — audit Remix configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

REMIX_CONFIG_NAMES = (
    "remix.config.js",
    "remix.config.ts",
    "remix.config.mjs",
    "remix.config.cjs",
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
REWRITE_INTERNAL_PATTERN = re.compile(
    r"(?:destination|source|target|proxy)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
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
WATCH_PATHS_PERMISSIVE_PATTERN = re.compile(
    r"watchPaths\s*:\s*\[[^\]]*(?:\.\./|['\"]\.\.['\"]|['\"]\*['\"])",
    re.IGNORECASE | re.DOTALL,
)
SERVER_BUILD_PATH_SENSITIVE_PATTERN = re.compile(
    r"serverBuildPath\s*:\s*['\"](?:\.\./|/etc|/var|/tmp)",
    re.IGNORECASE,
)
PUBLIC_PATH_HTTP_PATTERN = re.compile(
    r"publicPath\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
BASENAME_HTTP_PATTERN = re.compile(
    r"basename\s*:\s*['\"]http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
CORS_OPEN_PATTERN = re.compile(
    r"cors\s*:\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)
SOURCEMAP_TRUE_PATTERN = re.compile(
    r"(?:sourcemap|sourceMap)\s*:\s*(?:true|['\"]inline['\"]|['\"]hidden['\"])",
    re.IGNORECASE,
)


@dataclass
class RemixFinding:
    """A security or best-practice issue in a Remix configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class RemixInfo:
    """Parsed metadata about a Remix configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_server: bool = False
    has_dev: bool = False
    has_future: bool = False
    has_watch_paths: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class RemixStats:
    """Aggregate Remix analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_remix_file(path: Path) -> bool:
    return path.name in REMIX_CONFIG_NAMES or path.name.startswith("remix.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_remix_project(root: Path) -> bool:
    if any((root / name).exists() for name in REMIX_CONFIG_NAMES):
        return True
    if any(root.glob("remix.config.*")):
        return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(
                k in deps for k in ("@remix-run/dev", "@remix-run/node", "remix")
            ):
                return True
        except json.JSONDecodeError:
            pass
    return False


class RemixAnalyzer:
    """Audit Remix configuration for security and production risks.

    Scans remix.config.* files for hardcoded secrets, exposed dev servers,
    permissive watchPaths, internal proxy targets, and production sourcemaps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[RemixFinding] | None = None
        self._stats: RemixStats | None = None
        self._infos: list[RemixInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Remix configuration paths found in the project."""
        found: list[Path] = []
        for name in REMIX_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("remix.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_remix_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[RemixFinding],
        info: RemixInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("server", "dev", "future", "watchPaths", "routes"):
            if section in stripped and ":" in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                attr = section.lower().replace("watchpaths", "watch_paths")
                if hasattr(info, f"has_{attr}"):
                    setattr(info, f"has_{attr}", True)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Remix config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Remix config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Remix config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Remix config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Remix config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Remix config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (REWRITE_INTERNAL_PATTERN, "proxy_internal", "high",
             "proxy/redirect to internal IP — SSRF risk in dev and production"),
            (PUBLIC_PATH_HTTP_PATTERN, "public_path_http", "high",
             "publicPath uses HTTP — assets may be loaded over insecure transport"),
            (BASENAME_HTTP_PATTERN, "basename_http", "high",
             "basename uses HTTP — canonical URLs should use HTTPS in production"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "dev server host exposed to all interfaces — restrict to localhost in dev"),
            (WATCH_PATHS_PERMISSIVE_PATTERN, "watch_paths_permissive", "medium",
             "watchPaths is permissive — dev server may watch sensitive parent directories"),
            (SERVER_BUILD_PATH_SENSITIVE_PATTERN, "server_build_path_sensitive", "medium",
             "serverBuildPath points to sensitive location — isolate build output"),
            (FS_ALLOW_PERMISSIVE_PATTERN, "fs_allow_permissive", "medium",
             "fs.allow is permissive — dev server may read sensitive paths"),
            (CORS_OPEN_PATTERN, "cors_open", "medium",
             "open CORS configuration — any origin may access dev server"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verification_disabled", "medium",
             "rejectUnauthorized disabled in proxy — TLS verification bypassed"),
            (SOURCEMAP_TRUE_PATTERN, "sourcemaps_enabled", "medium",
             "source maps enabled — may expose source in production bundles"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    RemixFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[RemixFinding], RemixInfo]:
        findings: list[RemixFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, RemixInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = RemixInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[RemixFinding]:
        """Scan Remix configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[RemixFinding] = []
        infos: list[RemixInfo] = []
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
        self._stats = RemixStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> RemixStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[RemixInfo]:
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
        """Scaffold a hardened remix.config.js template."""
        return """\
// Generated by DevAI RemixAnalyzer
/** @type {import('@remix-run/dev').AppConfig} */
export default {
  serverBuildPath: 'build/server',
  publicPath: 'https://example.com/build/',
  basename: '/',
  dev: {
    port: 3000,
    host: '127.0.0.1',
  },
  watchPaths: ['.'],
  future: {
    v3_fetcherPersist: true,
    v3_relativeSplatPath: true,
  },
};
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Remix: no configuration files found"
        return (
            f"Remix: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Remix configuration analysis:",
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
