"""LitestarAnalyzer — audit Litestar apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LITESTAR_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "asgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
)
LITESTAR_IMPORT_PATTERN = re.compile(
    r"(?:from\s+litestar|import\s+litestar|Litestar\s*\()",
    re.IGNORECASE,
)
LITESTAR_ROUTE_PATTERN = re.compile(
    r"(?:@(?:get|post|put|delete|patch|head|options)\b|Router\s*\()",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|token_secret)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
JWT_SECRET_HARDCODED_PATTERN = re.compile(
    r"JWTAuth\s*\([^)]*token_secret\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
CSRF_SECRET_HARDCODED_PATTERN = re.compile(
    r"CSRFConfig\s*\([^)]*secret\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"CORSConfig\s*\([^)]*allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True[\s\S]{0,120}allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"][\s\S]{0,120}allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:secure\s*=\s*False|httponly\s*=\s*False|samesite\s*=\s*['\"]none['\"])",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:httpx|requests|aiohttp)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"uvicorn\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:debug|reload)\s*=\s*True",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:get|post|put|delete|patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
OPENAPI_EXPOSED_PATTERN = re.compile(
    r"OpenAPIConfig\s*\([^)]*path\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"csrf_config\s*=\s*None|csrf\s*=\s*False",
    re.IGNORECASE,
)
ALLOWED_HOSTS_WILDCARD_PATTERN = re.compile(
    r"allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
RAW_SQL_PATTERN = re.compile(
    r"(?:execute|executemany|raw)\s*\(\s*(?:f?['\"]|text\s*\(\s*f?['\"])",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)


@dataclass
class LitestarFinding:
    """A security or best-practice issue in a Litestar application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LitestarInfo:
    """Parsed metadata about a Litestar application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_csrf: bool = False
    has_openapi: bool = False
    has_jwt: bool = False
    has_allowed_hosts: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class LitestarStats:
    """Aggregate Litestar analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in (".toml", ".json", ".yaml", ".yml"):
        return path.suffix.lstrip(".")
    return "unknown"


def _contains_litestar(text: str) -> bool:
    return bool(
        LITESTAR_IMPORT_PATTERN.search(text)
        or LITESTAR_ROUTE_PATTERN.search(text)
        or "Litestar(" in text
    )


def _looks_like_litestar_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "litestar" in text:
                return True
        except OSError:
            continue

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            deps = data.get("project", {}).get("dependencies", [])
            optional = data.get("project", {}).get("optional-dependencies", {})
            all_deps = list(deps) + [
                item for group in optional.values() for item in group
            ]
            if any("litestar" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in LITESTAR_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_litestar(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class LitestarAnalyzer:
    """Audit Litestar applications for security and production risks.

    Scans Litestar entry files, route handlers, and config for hardcoded JWT/CSRF
    secrets, open CORS, disabled CSRF, exposed OpenAPI docs, debug mode, raw SQL,
    SSRF targets, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LitestarFinding] | None = None
        self._stats: LitestarStats | None = None
        self._infos: list[LitestarInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Litestar application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in LITESTAR_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_litestar(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_litestar_project(self.root):
            for path in sorted(self.root.rglob("*.py")):
                if path in seen:
                    continue
                if any(part.startswith(".") for part in path.parts):
                    continue
                if any(
                    part in {"venv", ".venv", "node_modules", "__pycache__", ".tox", ".mypy_cache"}
                    for part in path.parts
                ):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_litestar(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LitestarFinding],
        info: LitestarInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for route_kw in ("@get", "@post", "@put", "@delete", "@patch", "Router("):
            if route_kw in stripped:
                if route_kw.rstrip("(") not in info.routes:
                    info.routes.append(route_kw.rstrip("("))

        if "CORSConfig" in stripped or "allow_origins" in stripped:
            info.has_cors = True
        if "CSRFConfig" in stripped or "csrf_config" in stripped:
            info.has_csrf = True
        if "OpenAPIConfig" in stripped or "openapi_config" in stripped:
            info.has_openapi = True
        if "JWTAuth" in stripped or "token_secret" in stripped:
            info.has_jwt = True
        if "allowed_hosts" in stripped:
            info.has_allowed_hosts = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Litestar app — use environment variables"),
            (JWT_SECRET_HARDCODED_PATTERN, "jwt_secret_hardcoded", "high",
             "hardcoded JWTAuth token_secret — use environment variables"),
            (CSRF_SECRET_HARDCODED_PATTERN, "csrf_secret_hardcoded", "high",
             "hardcoded CSRFConfig secret — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Litestar app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Litestar app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "insecure cookie settings — enable secure/httponly and avoid samesite='none'"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Litestar app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "uvicorn bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug/reload enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (OPENAPI_EXPOSED_PATTERN, "openapi_exposed", "medium",
             "OpenAPI docs path configured — restrict or disable in production"),
            (CSRF_DISABLED_PATTERN, "csrf_disabled", "high",
             "CSRF protection disabled — enable CSRFConfig for state-changing routes"),
            (ALLOWED_HOSTS_WILDCARD_PATTERN, "allowed_hosts_wildcard", "medium",
             "allowed_hosts includes '*' — restrict to trusted hostnames"),
            (RAW_SQL_PATTERN, "raw_sql", "high",
             "raw SQL execution — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    LitestarFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[LitestarFinding], LitestarInfo]:
        findings: list[LitestarFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, LitestarInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = LitestarInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        for pattern, kind, severity, message in (
            (JWT_SECRET_HARDCODED_PATTERN, "jwt_secret_hardcoded", "high",
             "hardcoded JWTAuth token_secret — use environment variables"),
            (CSRF_SECRET_HARDCODED_PATTERN, "csrf_secret_hardcoded", "high",
             "hardcoded CSRFConfig secret — use environment variables"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
        ):
            if pattern.search(raw_text) and not any(f.kind == kind for f in findings):
                findings.append(
                    LitestarFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[LitestarFinding]:
        """Scan Litestar application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LitestarFinding] = []
        infos: list[LitestarInfo] = []
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
        self._stats = LitestarStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> LitestarStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[LitestarInfo]:
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
        """Scaffold a hardened Litestar main.py entry template."""
        return """\
# Generated by DevAI LitestarAnalyzer
import os

from litestar import Litestar, get
from litestar.config.cors import CORSConfig
from litestar.config.csrf import CSRFConfig
from litestar.openapi import OpenAPIConfig
from litestar.response import Response


@get("/health")
async def health() -> Response:
    return Response({"status": "ok"})


app = Litestar(
    route_handlers=[health],
    debug=False,
    allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
    cors_config=CORSConfig(
        allow_origins=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    ),
    csrf_config=CSRFConfig(secret=os.environ["CSRF_SECRET"]),
    openapi_config=OpenAPIConfig(
        title="API",
        version="1.0.0",
        path="/docs" if os.environ.get("ENABLE_OPENAPI") == "1" else None,
    ),
)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Litestar: no application files found"
        return (
            f"Litestar: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Litestar application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"routes={','.join(info.routes) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
