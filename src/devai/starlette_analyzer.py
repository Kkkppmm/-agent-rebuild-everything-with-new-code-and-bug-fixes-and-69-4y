"""StarletteAnalyzer — audit Starlette apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

STARLETTE_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "asgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
)
STARLETTE_IMPORT_PATTERN = re.compile(
    r"(?:from\s+starlette|import\s+starlette|Starlette\s*\()",
    re.IGNORECASE,
)
STARLETTE_ROUTE_PATTERN = re.compile(
    r"(?:@(?:app|router)\.route\b|Route\s*\(|Mount\s*\(|Router\s*\()",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
SESSION_SECRET_HARDCODED_PATTERN = re.compile(
    r"SessionMiddleware\s*\([^)]*secret_key\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE | re.DOTALL,
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
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:same_site|samesite)\s*=\s*['\"]none['\"]",
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
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"(?:Route|@(?:app|router)\.route)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
STATIC_FILES_UNSAFE_PATTERN = re.compile(
    r"StaticFiles\s*\([^)]*directory\s*=\s*(?!['\"][./])",
    re.IGNORECASE,
)
STATIC_FILES_ROOT_PATTERN = re.compile(
    r"StaticFiles\s*\(\s*directory\s*=\s*['\"]/['\"]",
    re.IGNORECASE,
)
TRUSTED_HOST_DISABLED_PATTERN = re.compile(
    r"allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
AUTH_MIDDLEWARE_NO_BACKEND_PATTERN = re.compile(
    r"AuthenticationMiddleware\s*\(\s*[^,)]+\s*\)",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)


@dataclass
class StarletteFinding:
    """A security or best-practice issue in a Starlette application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class StarletteInfo:
    """Parsed metadata about a Starlette application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_https_redirect: bool = False
    has_trusted_host: bool = False
    has_session: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class StarletteStats:
    """Aggregate Starlette analysis statistics."""

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


def _contains_starlette(text: str) -> bool:
    return bool(
        STARLETTE_IMPORT_PATTERN.search(text)
        or STARLETTE_ROUTE_PATTERN.search(text)
        or "Starlette(" in text
    )


def _looks_like_starlette_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "starlette" in text:
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
            if any("starlette" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in STARLETTE_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_starlette(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class StarletteAnalyzer:
    """Audit Starlette applications for security and production risks.

    Scans Starlette entry files, routes, and middleware for hardcoded session
    secrets, open CORS, unsafe StaticFiles mounts, missing trusted hosts,
    debug/reload mode, SSRF targets, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[StarletteFinding] | None = None
        self._stats: StarletteStats | None = None
        self._infos: list[StarletteInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Starlette application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in STARLETTE_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_starlette(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_starlette_project(self.root):
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
                if _contains_starlette(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[StarletteFinding],
        info: StarletteInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for route_kw in ("Route(", "Mount(", "Router(", "@app.route", "@router.route"):
            if route_kw in stripped:
                if route_kw.rstrip("(") not in info.routes:
                    info.routes.append(route_kw.rstrip("("))

        if "CORSMiddleware" in stripped or "allow_origins" in stripped:
            info.has_cors = True
        if any(k in stripped for k in ("AuthenticationMiddleware", "AuthCredentials", "requires(")):
            info.has_auth = True
        if "HTTPSRedirectMiddleware" in stripped:
            info.has_https_redirect = True
        if "TrustedHostMiddleware" in stripped:
            info.has_trusted_host = True
        if "SessionMiddleware" in stripped:
            info.has_session = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Starlette app — use environment variables"),
            (SESSION_SECRET_HARDCODED_PATTERN, "session_secret_hardcoded", "high",
             "hardcoded SessionMiddleware secret_key — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Starlette app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Starlette app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (COOKIE_INSECURE_PATTERN, "cookie_samesite_none", "medium",
             "session samesite='none' — ensure secure cookies are enabled"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Starlette app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "uvicorn bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug/reload enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (STATIC_FILES_UNSAFE_PATTERN, "static_files_unsafe", "high",
             "StaticFiles directory from variable — path traversal risk"),
            (STATIC_FILES_ROOT_PATTERN, "static_files_root", "medium",
             "StaticFiles mounted at filesystem root — restrict directory scope"),
            (TRUSTED_HOST_DISABLED_PATTERN, "trusted_host_wildcard", "medium",
             "TrustedHostMiddleware allows all hosts — restrict allowed_hosts"),
            (AUTH_MIDDLEWARE_NO_BACKEND_PATTERN, "auth_middleware_weak", "medium",
             "AuthenticationMiddleware without explicit backend — verify auth is enforced"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    StarletteFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[StarletteFinding], StarletteInfo]:
        findings: list[StarletteFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, StarletteInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = StarletteInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if SESSION_SECRET_HARDCODED_PATTERN.search(raw_text):
            if not any(f.kind == "session_secret_hardcoded" for f in findings):
                findings.append(
                    StarletteFinding(
                        kind="session_secret_hardcoded",
                        severity="high",
                        message="hardcoded SessionMiddleware secret_key — use environment variables",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    StarletteFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[StarletteFinding]:
        """Scan Starlette application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[StarletteFinding] = []
        infos: list[StarletteInfo] = []
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
        self._stats = StarletteStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> StarletteStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[StarletteInfo]:
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
        """Scaffold a hardened Starlette main.py entry template."""
        return """\
# Generated by DevAI StarletteAnalyzer
import os

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route


async def health(request):
    return JSONResponse({"status": "ok"})


routes = [
    Route("/health", health, methods=["GET"]),
]

app = Starlette(routes=routes, debug=False)

app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    same_site="lax",
    https_only=True,
)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Starlette: no application files found"
        return (
            f"Starlette: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Starlette application analysis:",
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
