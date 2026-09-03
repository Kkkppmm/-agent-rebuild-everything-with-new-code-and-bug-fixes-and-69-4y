"""NestJSAnalyzer — audit NestJS apps and configs for security and production risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

NESTJS_ENTRY_NAMES = (
    "src/main.ts",
    "src/main.js",
    "src/main.mjs",
    "main.ts",
    "main.js",
    "main.mjs",
)
NESTJS_CONFIG_NAMES = (
    "nest-cli.json",
    "nest-cli.prod.json",
)
NESTJS_IMPORT_PATTERN = re.compile(
    r"(?:from|import|require)\s*\(?\s*['\"]@nestjs/(?:common|core|platform-express|"
    r"platform-fastify|jwt|passport|typeorm|config|swagger|graphql|schedule|"
    r"microservices|websockets|cache-manager|throttler|serve-static)[^'\"]*['\"]",
    re.IGNORECASE,
)
NESTJS_DECORATOR_PATTERN = re.compile(
    r"@(?:Module|Controller|Injectable|Get|Post|Put|Delete|Patch|Public|"
    r"UseGuards|SetMetadata|Cron|WebSocketGateway)\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret)\s*[=:]\s*"
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
    r"(?:enableCors|origin)\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['\"]\*['\"])|"
    r"origin\s*:\s*(?:true|['\"]\*['\"])",
    re.IGNORECASE | re.DOTALL,
)
JWT_SECRET_HARDCODED_PATTERN = re.compile(
    r"(?:secret|privateKey|signOptions)\s*:\s*['\"][^'\"${}]+['\"]",
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
    r"(?:fetch|got|axios|HttpService|httpService)\s*\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:app|server)\.listen\s*\(\s*(?:\d+\s*,\s*)?['\"]0\.0\.0\.0['\"]|"
    r"await\s+app\.listen\s*\(\s*\d+\s*,\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
TYPEORM_SYNC_PATTERN = re.compile(
    r"synchronize\s*:\s*true",
    re.IGNORECASE,
)
VALIDATION_WHITELIST_FALSE_PATTERN = re.compile(
    r"whitelist\s*:\s*false",
    re.IGNORECASE,
)
VALIDATION_FORBID_FALSE_PATTERN = re.compile(
    r"forbidNonWhitelisted\s*:\s*false",
    re.IGNORECASE,
)
VALIDATION_DISABLED_PATTERN = re.compile(
    r"(?:disableValidation|skipMissingProperties)\s*:\s*true",
    re.IGNORECASE,
)
SWAGGER_EXPOSED_PATTERN = re.compile(
    r"SwaggerModule\.setup\s*\(\s*['\"](?:api|docs|swagger)['\"]",
    re.IGNORECASE,
)
GRAPHQL_PLAYGROUND_PATTERN = re.compile(
    r"playground\s*:\s*true|introspection\s*:\s*true",
    re.IGNORECASE,
)
PUBLIC_ADMIN_ROUTE_PATTERN = re.compile(
    r"@Public\s*\(\s*\)[\s\S]{0,200}@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"(?:csrf|csrfProtection)\s*:\s*false",
    re.IGNORECASE,
)
HELMET_DISABLED_PATTERN = re.compile(
    r"(?:contentSecurityPolicy|hsts|xFrameOptions)\s*:\s*false",
    re.IGNORECASE,
)
THROTTLE_DISABLED_PATTERN = re.compile(
    r"(?:throttle|rateLimit|limit)\s*:\s*0\b",
    re.IGNORECASE,
)
BODY_LIMIT_DISABLED_PATTERN = re.compile(
    r"(?:limit|bodyParser|rawBody)\s*:\s*(?:false|0\b|['\"]infinity['\"])",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:debug|logging)\s*:\s*true",
    re.IGNORECASE,
)
TRUST_PROXY_PATTERN = re.compile(
    r"trustProxy\s*:\s*true|set\s*\(\s*['\"]trust proxy['\"]\s*,\s*true\)",
    re.IGNORECASE,
)


@dataclass
class NestJSFinding:
    """A security or best-practice issue in a NestJS application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NestJSInfo:
    """Parsed metadata about a NestJS application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_helmet: bool = False
    has_throttle: bool = False
    has_validation: bool = False
    decorators: list[str] = field(default_factory=list)


@dataclass
class NestJSStats:
    """Aggregate NestJS analysis statistics."""

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


def _contains_nestjs(text: str) -> bool:
    return bool(
        NESTJS_IMPORT_PATTERN.search(text)
        or NESTJS_DECORATOR_PATTERN.search(text)
        or "NestFactory" in text
    )


def _looks_like_nestjs_project(root: Path) -> bool:
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(deps, dict) and any(
                k == "@nestjs/core" or k.startswith("@nestjs/") for k in deps
            ):
                return True
        except json.JSONDecodeError:
            pass
    for name in NESTJS_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_nestjs(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return any((root / name).is_file() for name in NESTJS_CONFIG_NAMES)


class NestJSAnalyzer:
    """Audit NestJS applications for security and production risks.

    Scans NestJS entry files, modules, and controllers for hardcoded JWT secrets,
    open CORS, disabled validation, TypeORM synchronize, exposed Swagger/GraphQL
    playgrounds, unprotected admin routes, and internal SSRF targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NestJSFinding] | None = None
        self._stats: NestJSStats | None = None
        self._infos: list[NestJSInfo] | None = None

    def configs(self) -> list[Path]:
        """Return NestJS application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in NESTJS_ENTRY_NAMES + NESTJS_CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_nestjs(text) or name in NESTJS_CONFIG_NAMES:
                    found.append(path)
                    seen.add(path)

        if _looks_like_nestjs_project(self.root):
            for path in sorted(self.root.rglob("*")):
                if not path.is_file() or path in seen:
                    continue
                if path.suffix not in (".ts", ".js", ".mjs", ".mts", ".cjs", ".json"):
                    continue
                if any(part.startswith(".") for part in path.parts):
                    continue
                if "node_modules" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_nestjs(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NestJSFinding],
        info: NestJSInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for decorator in (
            "Module",
            "Controller",
            "Injectable",
            "Get",
            "Post",
            "Public",
            "UseGuards",
        ):
            if f"@{decorator}" in stripped:
                if decorator not in info.decorators:
                    info.decorators.append(decorator)

        if "enableCors" in stripped or "Cors" in stripped:
            info.has_cors = True
        if any(k in stripped for k in ("JwtModule", "PassportModule", "AuthGuard", "@UseGuards")):
            info.has_auth = True
        if "helmet" in stripped.lower():
            info.has_helmet = True
        if any(k in stripped for k in ("ThrottlerModule", "ThrottlerGuard", "@Throttle")):
            info.has_throttle = True
        if "ValidationPipe" in stripped:
            info.has_validation = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in NestJS app — use ConfigService or environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in NestJS app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in NestJS app — use HTTPS"),
            (JWT_SECRET_HARDCODED_PATTERN, "jwt_secret_hardcoded", "high",
             "hardcoded JWT secret — use ConfigService or environment variables"),
            (UNSAFE_ENV_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — remove NODE_TLS_REJECT_UNAUTHORIZED=0"),
            (CURL_PIPE_SHELL_PATTERN, "curl_pipe_shell", "high",
             "curl|sh pattern in NestJS app — avoid piping remote scripts"),
            (DANGEROUS_SCRIPT_PATTERN, "dangerous_script", "high",
             "dangerous shell command in NestJS app"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval() in NestJS app — avoid dynamic code execution"),
            (PROXY_INTERNAL_PATTERN, "proxy_internal", "high",
             "request to internal IP — SSRF risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "rejectUnauthorized disabled — TLS verification bypassed"),
            (TYPEORM_SYNC_PATTERN, "typeorm_synchronize", "high",
             "TypeORM synchronize enabled — may drop or alter production schema"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
             "wildcard or permissive CORS origin — any site may access API responses"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "cookie secure flag disabled — cookies may be sent over HTTP"),
            (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
             "cookie httpOnly disabled — XSS may steal session cookies"),
            (VALIDATION_WHITELIST_FALSE_PATTERN, "validation_whitelist_false", "medium",
             "ValidationPipe whitelist disabled — extra properties may be injected"),
            (VALIDATION_FORBID_FALSE_PATTERN, "validation_forbid_false", "medium",
             "forbidNonWhitelisted disabled — mass assignment risk"),
            (VALIDATION_DISABLED_PATTERN, "validation_disabled", "medium",
             "input validation disabled — injection and mass assignment risk"),
            (SWAGGER_EXPOSED_PATTERN, "swagger_exposed", "medium",
             "Swagger UI exposed — restrict to non-production environments"),
            (GRAPHQL_PLAYGROUND_PATTERN, "graphql_playground", "medium",
             "GraphQL playground or introspection enabled — restrict in production"),
            (TRUST_PROXY_PATTERN, "trust_proxy", "medium",
             "trust proxy enabled — verify X-Forwarded-* headers are from trusted proxies"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "server bound to 0.0.0.0 — restrict to localhost in development"),
            (BODY_LIMIT_DISABLED_PATTERN, "body_limit_disabled", "medium",
             "body limit disabled — denial-of-service risk from unbounded payloads"),
            (HELMET_DISABLED_PATTERN, "helmet_disabled", "medium",
             "security header disabled in helmet config"),
            (CSRF_DISABLED_PATTERN, "csrf_disabled", "medium",
             "CSRF protection disabled — cookie-based auth may be vulnerable"),
            (DEBUG_MODE_PATTERN, "debug_mode", "low",
             "debug or verbose logging enabled — may leak sensitive data"),
            (THROTTLE_DISABLED_PATTERN, "throttle_disabled", "low",
             "rate limiting disabled — API may be vulnerable to abuse"),
            (SAME_SITE_NONE_PATTERN, "same_site_none", "low",
             "sameSite=none cookie — ensure secure flag is set"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    NestJSFinding(
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
                NestJSFinding(
                    kind="unprotected_admin_route",
                    severity="medium",
                    message="admin/debug/internal route — ensure AuthGuard or role checks are applied",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[NestJSFinding], NestJSInfo]:
        findings: list[NestJSFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NestJSInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = NestJSInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if PUBLIC_ADMIN_ROUTE_PATTERN.search(raw_text):
            findings.append(
                NestJSFinding(
                    kind="public_admin_route",
                    severity="high",
                    message="@Public() on admin/debug route — authentication bypass risk",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[NestJSFinding]:
        """Scan NestJS application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NestJSFinding] = []
        infos: list[NestJSInfo] = []
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
        self._stats = NestJSStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NestJSStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NestJSInfo]:
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
        """Scaffold a hardened NestJS main.ts entry template."""
        return """\
// Generated by DevAI NestJSAnalyzer
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.use(helmet());
  app.enableCors({
    origin: config.get<string>('ALLOWED_ORIGIN', 'https://example.com'),
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const port = config.get<number>('PORT', 3000);
  const host = config.get<string>('HOST', '127.0.0.1');
  await app.listen(port, host);
}

bootstrap();
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "NestJS: no application files found"
        return (
            f"NestJS: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "NestJS application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"decorators={','.join(info.decorators) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
