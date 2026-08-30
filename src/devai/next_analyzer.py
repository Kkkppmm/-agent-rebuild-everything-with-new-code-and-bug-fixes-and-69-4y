"""NextAnalyzer — audit Next.js configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

NEXT_CONFIG_NAMES = (
    "next.config.js",
    "next.config.ts",
    "next.config.mjs",
    "next.config.mts",
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
PRODUCTION_SOURCEMAPS_PATTERN = re.compile(
    r"productionBrowserSourceMaps\s*:\s*true",
    re.IGNORECASE,
)
IGNORE_BUILD_ERRORS_PATTERN = re.compile(
    r"(?:typescript|eslint)\s*:\s*\{[^}]*ignore(?:BuildErrors|DuringBuilds)\s*:\s*true",
    re.IGNORECASE | re.DOTALL,
)
IGNORE_TYPESCRIPT_ERRORS_PATTERN = re.compile(
    r"ignoreBuildErrors\s*:\s*true",
    re.IGNORECASE,
)
IGNORE_ESLINT_PATTERN = re.compile(
    r"ignoreDuringBuilds\s*:\s*true",
    re.IGNORECASE,
)
POWERED_BY_HEADER_PATTERN = re.compile(
    r"poweredByHeader\s*:\s*true",
    re.IGNORECASE,
)
DANGEROUSLY_ALLOW_SVG_PATTERN = re.compile(
    r"dangerouslyAllowSVG\s*:\s*true",
    re.IGNORECASE,
)
CSP_DISABLED_PATTERN = re.compile(
    r"contentSecurityPolicy\s*:\s*false",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|allowedOrigins)\s*:\s*['\"]\*['\"]|"
    r"key\s*:\s*['\"]Access-Control-Allow-Origin['\"][^}]*value\s*:\s*['\"]\*['\"]",
    re.IGNORECASE,
)
REWRITE_INTERNAL_PATTERN = re.compile(
    r"(?:destination|source|target)\s*:\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
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
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
ALLOWED_DEV_ORIGINS_WILDCARD_PATTERN = re.compile(
    r"allowedDevOrigins\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
SERVER_ACTIONS_ORIGINS_WILDCARD_PATTERN = re.compile(
    r"allowedOrigins\s*:\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
TRAILING_SLASH_FALSE_PATTERN = re.compile(
    r"trailingSlash\s*:\s*false",
    re.IGNORECASE,
)
UNOPTIMIZED_IMAGES_PATTERN = re.compile(
    r"unoptimized\s*:\s*true",
    re.IGNORECASE,
)
OUTPUT_STANDALONE_MISSING_PATTERN = re.compile(
    r"output\s*:\s*['\"]export['\"]",
    re.IGNORECASE,
)


@dataclass
class NextFinding:
    """A security or best-practice issue in a Next.js configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NextInfo:
    """Parsed metadata about a Next.js configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_images: bool = False
    has_rewrites: bool = False
    has_headers: bool = False
    has_env: bool = False
    has_experimental: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class NextStats:
    """Aggregate Next.js analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_next_file(path: Path) -> bool:
    return path.name in NEXT_CONFIG_NAMES or path.name.startswith("next.config.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    return "unknown"


def _looks_like_next_project(root: Path) -> bool:
    if any((root / name).exists() for name in NEXT_CONFIG_NAMES):
        return True
    for pattern in ("next.config.*",):
        if any(root.glob(pattern)):
            return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = data.get("dependencies", {})
            if isinstance(deps, dict) and "next" in deps:
                return True
        except json.JSONDecodeError:
            pass
    return False


class NextAnalyzer:
    """Audit Next.js configuration for security and production risks.

    Scans next.config.* files for hardcoded secrets, production sourcemaps,
    disabled type/lint checks, permissive image remote patterns, internal
    rewrites, open CORS, disabled CSP, and dangerous SVG handling.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NextFinding] | None = None
        self._stats: NextStats | None = None
        self._infos: list[NextInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Next.js configuration paths found in the project."""
        found: list[Path] = []
        for name in NEXT_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for pattern in ("next.config.*",):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found and _is_next_file(path):
                    found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NextFinding],
        info: NextInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("images", "rewrites", "headers", "env", "experimental"):
            if section in stripped and ":" in stripped:
                info.sections.append(section) if section not in info.sections else None
                setattr(info, f"has_{section}", True)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Next.js config — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Next.js config — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Next.js config — use HTTPS"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Next.js config — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Next.js config"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Next.js config — avoid dynamic code execution"),
            (ENV_SECRET_PATTERN, "env_secret", "high",
             "secret value in env block — use runtime environment variables"),
            (REWRITE_INTERNAL_PATTERN, "rewrite_internal", "high",
             "rewrite/redirect to internal IP — SSRF risk in dev and production"),
            (PRODUCTION_SOURCEMAPS_PATTERN, "production_sourcemaps", "medium",
             "productionBrowserSourceMaps enabled — exposes source in production"),
            (IGNORE_TYPESCRIPT_ERRORS_PATTERN, "ignore_typescript_errors", "medium",
             "TypeScript build errors ignored — type safety bypassed in production"),
            (IGNORE_ESLINT_PATTERN, "ignore_eslint", "medium",
             "ESLint ignored during builds — lint issues may reach production"),
            (DANGEROUSLY_ALLOW_SVG_PATTERN, "dangerously_allow_svg", "medium",
             "dangerouslyAllowSVG enabled — SVG XSS risk without strict CSP"),
            (CSP_DISABLED_PATTERN, "csp_disabled", "medium",
             "contentSecurityPolicy disabled — XSS protections weakened"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
             "wildcard CORS origin — any site may access API responses"),
            (REMOTE_PATTERN_WILDCARD_PATTERN, "remote_pattern_wildcard", "medium",
             "images.remotePatterns hostname set to * — allows any image origin"),
            (REMOTE_PATTERN_HTTP_PATTERN, "remote_pattern_http", "medium",
             "images.remotePatterns uses HTTP — images loaded over insecure transport"),
            (ALLOWED_DEV_ORIGINS_WILDCARD_PATTERN, "allowed_dev_origins_wildcard", "medium",
             "allowedDevOrigins includes * — dev server accepts any origin"),
            (SERVER_ACTIONS_ORIGINS_WILDCARD_PATTERN, "server_actions_origins_wildcard", "medium",
             "serverActions.allowedOrigins includes * — CSRF protection weakened"),
            (OUTPUT_STANDALONE_MISSING_PATTERN, "static_export", "low",
             "output: 'export' — static export may not suit dynamic apps; verify intent"),
            (POWERED_BY_HEADER_PATTERN, "powered_by_header", "low",
             "poweredByHeader enabled — exposes Next.js version to clients"),
            (UNOPTIMIZED_IMAGES_PATTERN, "unoptimized_images", "low",
             "images.unoptimized enabled — larger payloads and slower LCP"),
            (TRAILING_SLASH_FALSE_PATTERN, "trailing_slash_false", "low",
             "trailingSlash disabled — may cause redirect loops behind proxies"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    NextFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if IGNORE_BUILD_ERRORS_PATTERN.search(line):
            findings.append(
                NextFinding(
                    kind="ignore_build_checks",
                    severity="medium",
                    message="TypeScript or ESLint checks disabled during builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[NextFinding], NextInfo]:
        findings: list[NextFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NextInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = NextInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[NextFinding]:
        """Scan Next.js configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NextFinding] = []
        infos: list[NextInfo] = []
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
        self._stats = NextStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NextStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NextInfo]:
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
        """Scaffold a hardened next.config.ts template."""
        return """\
// Generated by DevAI NextAnalyzer
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  typescript: { ignoreBuildErrors: false },
  eslint: { ignoreDuringBuilds: false },
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'example.com', pathname: '/images/**' },
    ],
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },
  experimental: {
    serverActions: {
      allowedOrigins: ['https://example.com'],
    },
  },
};

export default nextConfig;
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Next.js: no configuration files found"
        return (
            f"Next.js: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Next.js configuration analysis:",
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
