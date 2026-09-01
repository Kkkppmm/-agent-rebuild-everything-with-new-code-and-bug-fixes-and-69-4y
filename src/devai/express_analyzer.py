"""ExpressAnalyzer — audit Express.js apps and configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

EXPRESS_ENTRY_NAMES = (
    "src/index.ts",
    "src/index.js",
    "src/index.mjs",
    "src/app.ts",
    "src/app.js",
    "src/server.ts",
    "src/server.js",
    "app.ts",
    "app.js",
    "server.ts",
    "server.js",
    "index.ts",
    "index.js",
)
EXPRESS_IMPORT_PATTERN = re.compile(
    r"(?:from|import|require)\s*\(?\s*['\"]express(?:/[^'\"]*)?['\"]",
    re.IGNORECASE,
)
EXPRESS_MIDDLEWARE_PATTERN = re.compile(
    r"(?:from|import|require)\s*\(?\s*['\"](?:cors|helmet|express-session|"
    r"cookie-parser|express-rate-limit|morgan|compression|body-parser)['\"]",
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
    r"(?:origin\s*:\s*(?:true|['\"]\*['\"])|allowedOrigins\s*:\s*\[[^\]]*['\"]\*['\"])",
    re.IGNORECASE,
)
SESSION_SECRET_HARDCODED_PATTERN = re.compile(
    r"(?:secret|sessionSecret|cookieSecret)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
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
    r"(?:fetch|got|axios|request)\s*\(\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:app|server)\.listen\s*\(\s*(?:\d+\s*,\s*)?['\"]0\.0\.0\.0['\"]|"
    r"host\s*:\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
TRUST_PROXY_PATTERN = re.compile(
    r"(?:app|express)\.set\s*\(\s*['\"]trust proxy['\"]\s*,\s*true\)",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"(?:app|router)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['\"]/(?:admin|debug|internal)",
    re.IGNORECASE,
)
BODY_LIMIT_DISABLED_PATTERN = re.compile(
    r"(?:limit|bodyParser)\s*:\s*(?:false|0\b|['\"]infinity['\"])",
    re.IGNORECASE,
)
SENSITIVE_STATIC_PATTERN = re.compile(
    r"express\.static\s*\(\s*['\"](?:/|\./|\.\./|/etc|/var|/home|/root)",
    re.IGNORECASE,
)
BASIC_AUTH_HARDCODED_PATTERN = re.compile(
    r"(?:username|password|user|pass)\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
RATE_LIMIT_DISABLED_PATTERN = re.compile(
    r"(?:max|windowMs|rateLimit)\s*:\s*0\b",
    re.IGNORECASE,
)
HELMET_DISABLED_PATTERN = re.compile(
    r"(?:contentSecurityPolicy|hsts|xFrameOptions)\s*:\s*false",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"(?:csrf|csurf)\s*\(\s*\{[^}]*(?:ignoreMethods|cookie)\s*:\s*false",
    re.IGNORECASE | re.DOTALL,
)
SAVE_UNINITIALIZED_PATTERN = re.compile(
    r"saveUninitialized\s*:\s*true",
    re.IGNORECASE,
)
RES_SAVE_UNINITIALIZED_PATTERN = re.compile(
    r"resave\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class ExpressFinding:
    """A security or best-practice issue in an Express application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ExpressInfo:
    """Parsed metadata about an Express application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_helmet: bool = False
    has_rate_limit: bool = False
    middleware: list[str] = field(default_factory=list)


@dataclass
class ExpressStats:
    """Aggregate Express analysis statistics."""

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
    if name.endswith(".json"):
        return "json"
    return "unknown"


def _contains_express(text: str) -> bool:
    return bool(EXPRESS_IMPORT_PATTERN.search(text) or EXPRESS_MIDDLEWARE_PATTERN.search(text))


def _looks_like_express_project(root: Path) -> bool:
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and "express" in deps:
                return True
        except json.JSONDecodeError:
            pass
    for name in EXPRESS_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_express(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class ExpressAnalyzer:
    """Audit Express.js applications for security and production risks.

    Scans Express entry files and middleware registrations for hardcoded session
    secrets, open CORS, insecure cookies, disabled body limits, unprotected admin
    routes, internal proxy targets, and missing security headers.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ExpressFinding] | None = None
        self._stats: ExpressStats | None = None
        self._infos: list[ExpressInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Express application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in EXPRESS_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_express(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_express_project(self.root):
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
                if _contains_express(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ExpressFinding],
        info: ExpressInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for mw in (
            "cors",
            "helmet",
            "express-session",
            "cookie-parser",
            "express-rate-limit",
            "morgan",
            "compression",
            "body-parser",
        ):
            if mw in stripped:
                if mw not in info.middleware:
                    info.middleware.append(mw)
                if mw == "cors":
                    info.has_cors = True
                elif mw in ("express-session", "cookie-parser"):
                    info.has_auth = True
                elif mw == "helmet":
                    info.has_helmet = True
                elif mw == "express-rate-limit":
                    info.has_rate_limit = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Express app — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Express app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Express app — use HTTPS"),
            (SESSION_SECRET_HARDCODED_PATTERN, "session_secret_hardcoded", "high",
             "hardcoded session secret — use environment variables or secret stores"),
            (BASIC_AUTH_HARDCODED_PATTERN, "basic_auth_hardcoded", "high",
             "hardcoded basic auth credentials — use environment variables"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in Express app — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in Express app"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in Express app — avoid dynamic code execution"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "request to internal IP — SSRF risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "rejectUnauthorized disabled — TLS verification bypassed"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
             "wildcard or permissive CORS origin — any site may access API responses"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "cookie secure flag disabled — cookies may be sent over HTTP"),
            (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
             "cookie httpOnly disabled — XSS may steal session cookies"),
            (TRUST_PROXY_PATTERN, "trust_proxy", "medium",
             "trust proxy enabled — verify X-Forwarded-* headers are from trusted proxies"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "server bound to 0.0.0.0 — restrict to localhost in development"),
            (BODY_LIMIT_DISABLED_PATTERN, "body_limit_disabled", "medium",
             "body limit disabled — denial-of-service risk from unbounded payloads"),
            (SENSITIVE_STATIC_PATTERN, "sensitive_static_root", "medium",
             "static file root may expose sensitive directories"),
            (HELMET_DISABLED_PATTERN, "helmet_disabled", "medium",
             "security header disabled in helmet config"),
            (SAVE_UNINITIALIZED_PATTERN, "save_uninitialized", "medium",
             "saveUninitialized enabled — session fixation risk"),
            (RES_SAVE_UNINITIALIZED_PATTERN, "resave_enabled", "low",
             "resave enabled — unnecessary session store writes"),
            (RATE_LIMIT_DISABLED_PATTERN, "rate_limit_disabled", "low",
             "rate limiting disabled — API may be vulnerable to abuse"),
            (SAME_SITE_NONE_PATTERN, "same_site_none", "low",
             "sameSite=none cookie — ensure secure flag is set"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    ExpressFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if DANGEROUS_ROUTE_PATTERN.search(line):
            findings.append(
                ExpressFinding(
                    kind="unprotected_admin_route",
                    severity="medium",
                    message="admin/debug/internal route — ensure authentication middleware is applied",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[ExpressFinding], ExpressInfo]:
        findings: list[ExpressFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ExpressInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = ExpressInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[ExpressFinding]:
        """Scan Express application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ExpressFinding] = []
        infos: list[ExpressInfo] = []
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
        self._stats = ExpressStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ExpressStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ExpressInfo]:
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
        """Scaffold a hardened Express app entry template."""
        return """\
// Generated by DevAI ExpressAnalyzer
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', false);

app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN ?? 'https://example.com',
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET ?? '',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
  },
}));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.use('/admin', (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '127.0.0.1';
app.listen(port, host, () => {
  console.log(`Listening on http://${host}:${port}`);
});
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Express: no application files found"
        return (
            f"Express: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Express application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"middleware={','.join(info.middleware) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
