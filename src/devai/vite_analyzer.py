"""ViteAnalyzer — audit Vite build configs for security risks."""

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
    r"(?:[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
ALLOWED_HOSTS_ALL_PATTERN = re.compile(
    r"allowedHosts\s*:\s*(?:true|\[[^\]]*[\"']\*[\"'])",
    re.IGNORECASE,
)
HOST_TRUE_PATTERN = re.compile(
    r"(?:server|preview)\s*:\s*\{[^}]*\bhost\s*:\s*true\b",
    re.IGNORECASE | re.DOTALL,
)
FS_STRICT_FALSE_PATTERN = re.compile(
    r"fs\s*:\s*\{[^}]*\bstrict\s*:\s*false\b",
    re.IGNORECASE | re.DOTALL,
)
CORS_CREDENTIALS_PATTERN = re.compile(
    r"cors\s*:\s*(?:true|\{[^}]*credentials\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)
DEFINE_SECRET_PATTERN = re.compile(
    r"define\s*:\s*\{[^}]*(?:SECRET|API_KEY|TOKEN|PASSWORD)",
    re.IGNORECASE | re.DOTALL,
)
PROXY_INSECURE_PATTERN = re.compile(
    r"proxy\s*:\s*\{[^}]*target\s*:\s*[\"']http://",
    re.IGNORECASE | re.DOTALL,
)
HTTPS_FALSE_PATTERN = re.compile(
    r"https\s*:\s*false\b",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
OPEN_REMOTE_PATTERN = re.compile(
    r"open\s*:\s*[\"']https?://",
    re.IGNORECASE,
)
SOURCEMAP_INLINE_PATTERN = re.compile(
    r"sourcemap\s*:\s*[\"']?inline[\"']?",
    re.IGNORECASE,
)
MINIFY_FALSE_PATTERN = re.compile(
    r"minify\s*:\s*false\b",
    re.IGNORECASE,
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
    has_server_block: bool = False
    has_build_block: bool = False
    plugins: list[str] = field(default_factory=list)


@dataclass
class ViteStats:
    """Aggregate Vite analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vite_file(path: Path) -> bool:
    return path.name in VITE_CONFIG_NAMES or path.name.startswith("vite.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts"):
        return "typescript"
    if name.endswith(".mts"):
        return "typescript-module"
    if name.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    return "unknown"


def _looks_like_vite_project(root: Path) -> bool:
    if any((root / name).is_file() for name in VITE_CONFIG_NAMES):
        return True
    if any(root.glob("vite.config.*")):
        return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            for key in ("devDependencies", "dependencies"):
                block = data.get(key, {})
                if isinstance(block, dict) and "vite" in block:
                    return True
        except (OSError, json.JSONDecodeError):
            pass
    return False


class ViteAnalyzer:
    """Audit Vite configuration for security and build hygiene risks.

    Scans vite.config.* for hardcoded secrets, permissive server settings,
    disabled filesystem strictness, insecure proxies, and sourcemap leaks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ViteFinding] | None = None
        self._stats: ViteStats | None = None
        self._infos: list[ViteInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Vite configuration paths found in the project."""
        if not _looks_like_vite_project(self.root):
            return []

        found: list[Path] = []
        for name in VITE_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.glob("vite.config.*")):
            if path.is_file() and path not in found:
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
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        if "server:" in stripped or "server :" in stripped:
            info.has_server_block = True
        if "build:" in stripped or "build :" in stripped:
            info.has_build_block = True

        plugin_match = re.search(r"(\w+)\s*\(\s*\)", stripped)
        if plugin_match and "plugins" in stripped:
            plugin = plugin_match.group(1)
            if plugin not in info.plugins:
                info.plugins.append(plugin)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Vite config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Vite config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in Vite config — use HTTPS endpoints"),
            (ALLOWED_HOSTS_ALL_PATTERN, "allowed_hosts_all", "high",
             "allowedHosts allows all hosts — restrict to known domains"),
            (HOST_TRUE_PATTERN, "host_true", "medium",
             "server/preview host:true exposes dev server on all interfaces"),
            (FS_STRICT_FALSE_PATTERN, "fs_strict_false", "high",
             "fs.strict:false allows serving files outside project root"),
            (CORS_CREDENTIALS_PATTERN, "cors_credentials", "medium",
             "permissive CORS with credentials — restrict origins in dev"),
            (DEFINE_SECRET_PATTERN, "define_secret", "high",
             "define block embeds secrets into client bundle — use import.meta.env"),
            (PROXY_INSECURE_PATTERN, "proxy_insecure", "medium",
             "proxy target uses HTTP — use HTTPS for upstream services"),
            (HTTPS_FALSE_PATTERN, "https_false", "medium",
             "https:false disables TLS for dev server — enable for sensitive data"),
            (EVAL_PATTERN, "eval", "high",
             "eval() in Vite config — avoid dynamic code execution"),
            (OPEN_REMOTE_PATTERN, "open_remote", "low",
             "open launches remote URL on dev start — prefer local paths"),
            (SOURCEMAP_INLINE_PATTERN, "sourcemap_inline", "medium",
             "inline sourcemaps leak source code in production bundles"),
            (MINIFY_FALSE_PATTERN, "minify_false", "low",
             "minify:false ships readable production bundles"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    ViteFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[ViteFinding], ViteInfo]:
        findings: list[ViteFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ViteInfo(path=rel, file_kind=_file_kind(path))

        info = ViteInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)
        return findings, info

    def analyze(self) -> list[ViteFinding]:
        """Scan Vite configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ViteFinding] = []
        infos: list[ViteInfo] = []
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
        self._stats = ViteStats(
            config_files=len(paths),
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
        """Scaffold a hardened Vite configuration template."""
        return """\
// Generated by DevAI ViteAnalyzer
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'localhost',
    https: true,
    cors: { origin: ['http://localhost:5173'], credentials: false },
    fs: { strict: true },
  },
  build: {
    sourcemap: false,
    minify: 'esbuild',
  },
  define: {
    // Use import.meta.env.VITE_* for client-side env vars
  },
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Vite configs: none found"
        return (
            f"Vite configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Vite analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: server={info.has_server_block}, build={info.has_build_block}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
