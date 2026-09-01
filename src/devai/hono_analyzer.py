"""HonoAnalyzer — audit Hono apps and configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

HONO_ENTRY_NAMES = (
    "src/index.ts",
    "src/index.js",
    "src/index.mjs",
    "src/app.ts",
    "src/app.js",
    "app.ts",
    "app.js",
    "server.ts",
    "server.js",
    "index.ts",
    "index.js",
)
WRANGLER_NAMES = (
    "wrangler.toml",
    "wrangler.json",
    "wrangler.jsonc",
)
VITE_CONFIG_NAMES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.mts",
)
HONO_IMPORT_PATTERN = re.compile(
    r"(?:from|import)\s+['\"]hono(?:/[^'\"]*)?['\"]",
    re.IGNORECASE,
)
HONO_VITE_PLUGIN_PATTERN = re.compile(
    r"(?:@hono/vite-dev-server|hono/vite|from\s+['\"]@hono/vite-dev-server['\"])",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret)\s*[=:]\s*"
    r"(?!\s*process\.env)(?:[\"']?[^\"'\s${}][^\"'<]*[\"']?)",
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
CORS_WILDCARD_PATTERN = re.compile(
    r"cors\s*\([^)]*origin\s*:\s*['\"]\*['\"]|cors\s*\(\s*['\"]\*['\"]\s*\)",
    re.IGNORECASE,
)
BASIC_AUTH_HARDCODED_PATTERN = re.compile(
    r"basicAuth\s*\(\s*\{[^}]*(?:username|password)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
BEARER_AUTH_HARDCODED_PATTERN = re.compile(
    r"bearerAuth\s*\(\s*\{[^}]*token\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
JWT_SECRET_HARDCODED_PATTERN = re.compile(
    r"jwt\s*\(\s*\{[^}]*secret\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"secure\s*:\s*false",
    re.IGNORECASE,
)
COOKIE_HTTPONLY_FALSE_PATTERN = re.compile(
    r"httpOnly\s*:\s*false",
    re.IGNORECASE,
)
SAME_SITE_NONE_PATTERN = re.compile(
    r"sameSite\s*:\s*['\"]none['\"]",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"rejectUnauthorized\s*:\s*false",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:target|proxy|destination|url)\s*[:=]\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"fetch\s*\(\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|CLIENT[_-]?SECRET)\s*[=:]\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
WRANGLER_SECRET_PATTERN = re.compile(
    r"(?:api[_-]?key|secret|token|password|credential)\s*=\s*['\"]?[^\"'\s${}][^\"'\n#]+",
    re.IGNORECASE,
)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:hostname|host)\s*=\s*['\"]0\.0\.0\.0['\"]|host\s*:\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
NODE_COMPAT_PATTERN = re.compile(
    r"compatibility_flags\s*=\s*\[[^\]]*nodejs_compat",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(\s*['\"]/(?:admin|debug|internal)",
    re.IGNORECASE,
)
TRUST_PROXY_PATTERN = re.compile(
    r"trustProxy\s*:\s*true",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"csrf\s*\(\s*\{[^}]*checkOrigin\s*:\s*false",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class HonoFinding:
    """A security or best-practice issue in a Hono application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HonoInfo:
    """Parsed metadata about a Hono application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_middleware: bool = False
    has_wrangler: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class HonoStats:
    """Aggregate Hono analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".ts") or name.endswith(".mts"):
        return "typescript"
    if name.endswith(".js") or name.endswith(".mjs") or name.endswith(".cjs"):
        return "javascript"
    if name.endswith(".toml"):
        return "toml"
    if name.endswith(".json") or name.endswith(".jsonc"):
        return "json"
    return "unknown"


def _contains_hono(text: str) -> bool:
    return bool(HONO_IMPORT_PATTERN.search(text))


def _is_vite_hono_file(path: Path, text: str | None = None) -> bool:
    if path.name not in VITE_CONFIG_NAMES and not path.name.startswith("vite.config."):
        return False
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(HONO_VITE_PLUGIN_PATTERN.search(text))


def _looks_like_hono_project(root: Path) -> bool:
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(k.startswith("hono") for k in deps):
                return True
        except json.JSONDecodeError:
            pass
    for name in HONO_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_hono(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    if any((root / name).exists() for name in WRANGLER_NAMES):
        return True
    return False


class HonoAnalyzer:
    """Audit Hono applications for security and production risks.

    Scans Hono entry files, wrangler.toml, and vite.config.* (with Hono plugins)
    for hardcoded auth secrets, open CORS, insecure cookies, internal proxy
    targets, wrangler credential leaks, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HonoFinding] | None = None
        self._stats: HonoStats | None = None
        self._infos: list[HonoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Hono application and configuration paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in WRANGLER_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
                seen.add(path)

        for name in HONO_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_hono(text):
                    found.append(path)
                    seen.add(path)

        for pattern in VITE_CONFIG_NAMES:
            path = self.root / pattern
            if path.is_file() and path not in seen and _is_vite_hono_file(path):
                found.append(path)
                seen.add(path)

        if _looks_like_hono_project(self.root):
            for path in sorted(self.root.rglob("*")):
                if not path.is_file() or path in seen:
                    continue
                if path.suffix not in (".ts", ".js", ".mjs", ".mts", ".cjs"):
                    continue
                if any(part.startswith(".") for part in path.parts):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_hono(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HonoFinding],
        info: HonoInfo,
        is_wrangler: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for section in ("cors", "basicAuth", "bearerAuth", "jwt", "secureHeaders", "csrf"):
            if section in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "cors":
                    info.has_cors = True
                elif section in ("basicAuth", "bearerAuth", "jwt"):
                    info.has_auth = True
                elif section in ("secureHeaders", "csrf"):
                    info.has_middleware = True

        if is_wrangler:
            checks: list[tuple[re.Pattern[str], str, str, str]] = [
                (WRANGLER_SECRET_PATTERN, "wrangler_secret", "high",
                 "hardcoded secret in wrangler.toml — use wrangler secret put"),
                (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
                 "hardcoded secret in wrangler config — use secret bindings"),
                (INSECURE_HTTP_PATTERN, "insecure_http", "high",
                 "insecure HTTP URL in wrangler config — use HTTPS"),
                (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
                 "dev server bound to 0.0.0.0 — restrict to localhost in development"),
                (NODE_COMPAT_PATTERN, "nodejs_compat", "low",
                 "nodejs_compat flag enabled — review Node.js API surface in Workers"),
            ]
        else:
            checks = [
                (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
                 "hardcoded secret in Hono app — use environment variables or bindings"),
                (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
                 "AWS access key in Hono app — rotate and use secret stores"),
                (INSECURE_HTTP_PATTERN, "insecure_http", "high",
                 "insecure HTTP URL in Hono app — use HTTPS"),
                (BASIC_AUTH_HARDCODED_PATTERN, "basic_auth_hardcoded", "high",
                 "hardcoded basicAuth credentials — use environment variables"),
                (BEARER_AUTH_HARDCODED_PATTERN, "bearer_auth_hardcoded", "high",
                 "hardcoded bearerAuth token — use environment variables"),
                (JWT_SECRET_HARDCODED_PATTERN, "jwt_secret_hardcoded", "high",
                 "hardcoded JWT secret — use environment variables or secret bindings"),
                (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
                 "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
                (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
                 "curl|sh pattern in Hono app — avoid piping remote scripts"),
                (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
                 "dangerous shell command in Hono app"),
                (EVAL_PATTERN, "eval_usage", "high",
                 "eval() in Hono app — avoid dynamic code execution"),
                (ENV_SECRET_PATTERN, "env_secret", "high",
                 "secret value in env block — use runtime environment variables"),
                (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
                 "proxy/fetch to internal IP — SSRF risk"),
                (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
                 "rejectUnauthorized disabled — TLS verification bypassed"),
                (CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
                 "wildcard CORS origin — any site may access API responses"),
                (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
                 "cookie secure flag disabled — cookies may be sent over HTTP"),
                (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
                 "cookie httpOnly disabled — XSS may steal session cookies"),
                (CSRF_DISABLED_PATTERN, "csrf_disabled", "medium",
                 "CSRF origin check disabled — cross-site request forgery risk"),
                (TRUST_PROXY_PATTERN, "trust_proxy", "medium",
                 "trustProxy enabled — verify X-Forwarded-* headers are from trusted proxies"),
                (SAME_SITE_NONE_PATTERN, "same_site_none", "low",
                 "sameSite=none cookie — ensure secure flag is set"),
            ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    HonoFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if not is_wrangler and DANGEROUS_ROUTE_PATTERN.search(line):
            findings.append(
                HonoFinding(
                    kind="unprotected_admin_route",
                    severity="medium",
                    message="admin/debug/internal route — ensure authentication middleware is applied",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[HonoFinding], HonoInfo]:
        findings: list[HonoFinding] = []
        rel = str(path.relative_to(self.root))
        is_wrangler = path.name in WRANGLER_NAMES or path.name.startswith("wrangler.")
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, HonoInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = HonoInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
            has_wrangler=is_wrangler,
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_wrangler)

        return findings, info

    def analyze(self) -> list[HonoFinding]:
        """Scan Hono application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HonoFinding] = []
        infos: list[HonoInfo] = []
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
        self._stats = HonoStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HonoStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HonoInfo]:
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
        """Scaffold a hardened Hono app entry template."""
        return """\
// Generated by DevAI HonoAnalyzer
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { bearerAuth } from 'hono/bearer-auth';

const app = new Hono();

app.use('*', secureHeaders());
app.use(
  '/api/*',
  cors({
    origin: process.env.ALLOWED_ORIGIN ?? 'https://example.com',
    credentials: true,
  }),
);

app.get('/health', (c) => c.json({ status: 'ok' }));

app.use(
  '/admin/*',
  bearerAuth({ token: process.env.ADMIN_TOKEN ?? '' }),
);

export default app;
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Hono: no application files found"
        return (
            f"Hono: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Hono application analysis:",
            f"  files: {stats.configs}",
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
