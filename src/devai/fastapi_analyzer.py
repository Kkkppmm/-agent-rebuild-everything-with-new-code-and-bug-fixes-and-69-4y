"""FastAPIAnalyzer — audit FastAPI apps and configs for security and production risks."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

FASTAPI_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
    "app/server.py",
)
FASTAPI_IMPORT_PATTERN = re.compile(
    r"(?:from\s+fastapi|import\s+fastapi|FastAPI\s*\()",
    re.IGNORECASE,
)
FASTAPI_DECORATOR_PATTERN = re.compile(
    r"@(?:app|router)\.(?:get|post|put|delete|patch|head|options|api_route)\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|SecretStr))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"CORSMiddleware\([^)]*allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE | re.DOTALL,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True[\s\S]{0,120}allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"][\s\S]{0,120}allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
JWT_SECRET_HARDCODED_PATTERN = re.compile(
    r"(?:SECRET_KEY|secret_key|jwt_secret|JWT_SECRET)\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"secure\s*=\s*False",
    re.IGNORECASE,
)
COOKIE_HTTPONLY_FALSE_PATTERN = re.compile(
    r"httponly\s*=\s*False",
    re.IGNORECASE,
)
SAME_SITE_NONE_PATTERN = re.compile(
    r"samesite\s*=\s*['\"]none['\"]",
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
    r"(?:reload|debug)\s*=\s*True",
    re.IGNORECASE,
)
DOCS_EXPOSED_PATTERN = re.compile(
    r"(?:docs_url|redoc_url|openapi_url)\s*=\s*['\"]/",
    re.IGNORECASE,
)
VALIDATION_DISABLED_PATTERN = re.compile(
    r"response_model_exclude_unset\s*=\s*False|"
    r"arbitrary_types_allowed\s*=\s*True|"
    r"extra\s*=\s*['\"]allow['\"]",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
SQL_RAW_PATTERN = re.compile(
    r"(?:execute|text)\s*\(\s*f?['\"].*(?:SELECT|INSERT|UPDATE|DELETE)",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)
DEPENDENCY_OVERRIDE_PATTERN = re.compile(
    r"app\.dependency_overrides\s*\[",
    re.IGNORECASE,
)
TRUSTED_HOST_DISABLED_PATTERN = re.compile(
    r"allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
RATE_LIMIT_DISABLED_PATTERN = re.compile(
    r"(?:rate_limit|throttle)\s*=\s*(?:0|None)",
    re.IGNORECASE,
)


@dataclass
class FastAPIFinding:
    """A security or best-practice issue in a FastAPI application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class FastAPIInfo:
    """Parsed metadata about a FastAPI application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_https_redirect: bool = False
    has_trusted_host: bool = False
    has_rate_limit: bool = False
    decorators: list[str] = field(default_factory=list)


@dataclass
class FastAPIStats:
    """Aggregate FastAPI analysis statistics."""

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


def _contains_fastapi(text: str) -> bool:
    return bool(
        FASTAPI_IMPORT_PATTERN.search(text)
        or FASTAPI_DECORATOR_PATTERN.search(text)
        or "FastAPI(" in text
    )


def _looks_like_fastapi_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "fastapi" in text:
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
            if any("fastapi" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in FASTAPI_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_fastapi(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class FastAPIAnalyzer:
    """Audit FastAPI applications for security and production risks.

    Scans FastAPI entry files, routers, and settings for hardcoded secrets,
    open CORS, exposed docs, disabled validation, debug/reload mode, SSRF
    targets, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FastAPIFinding] | None = None
        self._stats: FastAPIStats | None = None
        self._infos: list[FastAPIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return FastAPI application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in FASTAPI_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_fastapi(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_fastapi_project(self.root):
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
                if _contains_fastapi(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[FastAPIFinding],
        info: FastAPIInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for decorator in ("get", "post", "put", "delete", "patch", "api_route"):
            if f".{decorator}(" in stripped or f"@{decorator}(" in stripped:
                if decorator not in info.decorators:
                    info.decorators.append(decorator)

        if "CORSMiddleware" in stripped or "allow_origins" in stripped:
            info.has_cors = True
        if any(k in stripped for k in ("OAuth2PasswordBearer", "HTTPBearer", "Depends(get_current_user)", "Security(")):
            info.has_auth = True
        if "HTTPSRedirectMiddleware" in stripped:
            info.has_https_redirect = True
        if "TrustedHostMiddleware" in stripped:
            info.has_trusted_host = True
        if any(k in stripped.lower() for k in ("slowapi", "rate_limit", "limiter")):
            info.has_rate_limit = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in FastAPI app — use environment variables or pydantic-settings"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in FastAPI app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in FastAPI app — use HTTPS"),
            (JWT_SECRET_HARDCODED_PATTERN, "jwt_secret_hardcoded", "high",
             "hardcoded JWT/secret key — use environment variables"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "cookie secure=False — set secure=True in production"),
            (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
             "cookie httponly=False — enable httponly for session cookies"),
            (SAME_SITE_NONE_PATTERN, "cookie_samesite_none", "medium",
             "cookie samesite='none' — ensure secure=True is set"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in FastAPI app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "uvicorn bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug/reload enabled — disable in production"),
            (DOCS_EXPOSED_PATTERN, "docs_exposed", "medium",
             "OpenAPI/Swagger docs exposed — disable or protect in production"),
            (VALIDATION_DISABLED_PATTERN, "validation_relaxed", "medium",
             "relaxed Pydantic validation — review model_config settings"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (DEPENDENCY_OVERRIDE_PATTERN, "dependency_override", "medium",
             "app.dependency_overrides used — remove before production deploy"),
            (TRUSTED_HOST_DISABLED_PATTERN, "trusted_host_wildcard", "medium",
             "TrustedHostMiddleware allows all hosts — restrict allowed_hosts"),
            (RATE_LIMIT_DISABLED_PATTERN, "rate_limit_disabled", "low",
             "rate limiting disabled — add throttling for public endpoints"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    FastAPIFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[FastAPIFinding], FastAPIInfo]:
        findings: list[FastAPIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, FastAPIInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = FastAPIInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    FastAPIFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[FastAPIFinding]:
        """Scan FastAPI application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FastAPIFinding] = []
        infos: list[FastAPIInfo] = []
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
        self._stats = FastAPIStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FastAPIStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FastAPIInfo]:
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
        """Scaffold a hardened FastAPI main.py entry template."""
        return """\
# Generated by DevAI FastAPIAnalyzer
import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str
    allowed_origins: list[str] = ["https://example.com"]
    allowed_hosts: list[str] = ["example.com", "www.example.com"]

    model_config = {"env_file": ".env"}


settings = Settings()

app = FastAPI(
    title="API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "FastAPI: no application files found"
        return (
            f"FastAPI: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "FastAPI application analysis:",
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
