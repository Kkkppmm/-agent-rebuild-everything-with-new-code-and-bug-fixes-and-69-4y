"""FastAPIAnalyzer — audit FastAPI applications for security and production risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

ENTRYPOINT_NAMES = ("main.py", "app.py", "application.py", "server.py")
FASTAPI_IMPORT_PATTERN = re.compile(
    r"(?:from\s+fastapi|import\s+fastapi)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|jwt[_-]?secret)\s*=\s*"
    r"['\"][^'\"${}\s][^'\"]*['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"['\"]?AKIA[0-9A-Z]{16}['\"]?", re.IGNORECASE)
DEBUG_TRUE_PATTERN = re.compile(
    r"(?:FastAPI\s*\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|"
    r"DEBUG\s*=\s*True|reload\s*=\s*True)",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"allow_origin_regex\s*=\s*['\"].*\*.*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
DOCS_NOT_DISABLED_PATTERN = re.compile(
    r"(?:docs_url|redoc_url|openapi_url)\s*=\s*['\"]/",
    re.IGNORECASE,
)
TRUSTED_HOST_WILDCARD_PATTERN = re.compile(
    r"allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"host\s*=\s*['\"](?:0\.0\.0\.0|::)['\"]|"
    r"uvicorn\.run\s*\([^)]*host\s*=\s*['\"](?:0\.0\.0\.0|::)['\"]",
    re.IGNORECASE,
)
SSRF_INTERNAL_PATTERN = re.compile(
    r"(?:httpx\.|requests\.|aiohttp\.|urllib\.request\.|client\.get|client\.post|"
    r"session\.get|session\.post)\s*\([^)]*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
TLS_VERIFY_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False|CERT_NONE",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(
    r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
    re.IGNORECASE,
)
SQL_FSTRING_PATTERN = re.compile(
    r"(?:execute|executemany|raw)\s*\(\s*f['\"]",
    re.IGNORECASE,
)
JWT_NONE_PATTERN = re.compile(
    r"algorithm\s*=\s*['\"]none['\"]|algorithms\s*=\s*\[[^\]]*['\"]none['\"]",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:httponly|secure)\s*=\s*False",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"pickle\.(?:loads?|Unpickler)|yaml\.load\s*\([^)]*Loader\s*=\s*None",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"RedirectResponse\s*\([^)]*request\.(?:query_params|url)",
    re.IGNORECASE,
)
RATE_LIMIT_MISSING_HINT = re.compile(
    r"@app\.(?:get|post|put|delete|patch)\s*\(",
    re.IGNORECASE,
)
SLOWAPI_PATTERN = re.compile(r"slowapi|Limiter|@limiter", re.IGNORECASE)


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
    has_cors: bool = False
    has_trusted_host: bool = False
    has_rate_limit: bool = False
    route_decorators: int = 0
    sections: list[str] = field(default_factory=list)


@dataclass
class FastAPIStats:
    """Aggregate FastAPI analysis statistics."""

    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_fastapi_project(root: Path) -> bool:
    pkg = root / "pyproject.toml"
    req = root / "requirements.txt"
    if pkg.is_file():
        try:
            text = pkg.read_text(encoding="utf-8", errors="replace")
            if "fastapi" in text.lower():
                return True
        except OSError:
            pass
    if req.is_file():
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
            if "fastapi" in text.lower():
                return True
        except OSError:
            pass
    for name in ENTRYPOINT_NAMES:
        if (root / name).is_file():
            try:
                text = (root / name).read_text(encoding="utf-8", errors="replace")
                if FASTAPI_IMPORT_PATTERN.search(text):
                    return True
            except OSError:
                pass
    return False


class FastAPIAnalyzer:
    """Audit FastAPI applications for security and production risks.

    Scans Python entrypoints and modules importing FastAPI for hardcoded secrets,
    debug mode, open CORS, exposed OpenAPI docs, SSRF-prone HTTP clients, TLS
    bypass, unsafe deserialization, and missing production hardening.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[FastAPIFinding] | None = None
        self._stats: FastAPIStats | None = None
        self._infos: list[FastAPIInfo] | None = None

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix.lower() != ".py"

    def files(self) -> list[Path]:
        """Return FastAPI-related Python paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in ENTRYPOINT_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    if FASTAPI_IMPORT_PATTERN.search(text) or "FastAPI(" in text:
                        found.append(path)
                        seen.add(path)
                except OSError:
                    pass

        if not _looks_like_fastapi_project(self.root) and not found:
            return found

        for path in sorted(self.root.rglob("*.py")):
            if self._should_skip(path) or path in seen:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if FASTAPI_IMPORT_PATTERN.search(text) or "FastAPI(" in text:
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

        if "CORSMiddleware" in line:
            info.has_cors = True
            info.sections.append("cors") if "cors" not in info.sections else None
        if "TrustedHostMiddleware" in line:
            info.has_trusted_host = True
            info.sections.append("trusted_host") if "trusted_host" not in info.sections else None
        if SLOWAPI_PATTERN.search(line):
            info.has_rate_limit = True
        if RATE_LIMIT_MISSING_HINT.search(line):
            info.route_decorators += 1

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in FastAPI app — use environment variables or secret stores"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in source — rotate and use IAM roles or secret stores"),
            (DEBUG_TRUE_PATTERN, "debug_enabled", "high",
             "debug/reload enabled — disable in production deployments"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins includes * — restrict to trusted origins"),
            (SSRF_INTERNAL_PATTERN, "ssrf_internal", "high",
             "HTTP client targets internal IP — SSRF risk in route handlers"),
            (TLS_VERIFY_FALSE_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — enable verify=True"),
            (EVAL_PATTERN, "eval_usage", "high",
             "eval/exec in FastAPI app — avoid dynamic code execution"),
            (SHELL_TRUE_PATTERN, "shell_true", "high",
             "subprocess with shell=True — command injection risk"),
            (SQL_FSTRING_PATTERN, "sql_fstring", "high",
             "SQL built with f-string — use parameterized queries"),
            (JWT_NONE_PATTERN, "jwt_none_algorithm", "high",
             "JWT algorithm 'none' — use strong signing algorithms (RS256, ES256)"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe parsers"),
            (TRUSTED_HOST_WILDCARD_PATTERN, "trusted_host_wildcard", "medium",
             "TrustedHostMiddleware allows * — restrict allowed_hosts"),
            (DOCS_NOT_DISABLED_PATTERN, "docs_exposed", "medium",
             "OpenAPI/ReDoc URL configured — disable docs in production (docs_url=None)"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in FastAPI app — use HTTPS endpoints"),
            (COOKIE_INSECURE_PATTERN, "insecure_cookie", "medium",
             "cookie httponly/secure disabled — enable secure session cookies"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "medium",
             "redirect from request URL/params — validate redirect targets"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "low",
             "server binds to all interfaces — ensure firewall and auth protect the service"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    FastAPIFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if CORS_WILDCARD_PATTERN.search(line) and CORS_CREDENTIALS_WILDCARD_PATTERN.search(line):
            findings.append(
                FastAPIFinding(
                    kind="cors_credentials_wildcard",
                    severity="high",
                    message="allow_credentials=True with permissive CORS — browsers may leak cookies",
                    path=rel,
                    lineno=lineno,
                    line=line,
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
        info = FastAPIInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if info.route_decorators >= 3 and not info.has_rate_limit and not SLOWAPI_PATTERN.search(raw_text):
            findings.append(
                FastAPIFinding(
                    kind="rate_limit_missing",
                    severity="low",
                    message="no rate limiting detected — consider slowapi or API gateway throttling",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.has_cors and not info.has_trusted_host and info.route_decorators > 0:
            findings.append(
                FastAPIFinding(
                    kind="trusted_host_missing",
                    severity="medium",
                    message="CORSMiddleware without TrustedHostMiddleware — add host header validation",
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
        paths = self.files()

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
        if stats.files == 0:
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
        """Scaffold a hardened FastAPI application template."""
        return """\
# Generated by DevAI FastAPIAnalyzer
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

DEBUG = os.getenv("DEBUG", "false").lower() == "true"

app = FastAPI(
    title="My API",
    debug=DEBUG,
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

origins = os.getenv("CORS_ORIGINS", "https://example.com").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return "FastAPI: no application files found"
        return (
            f"FastAPI: {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "FastAPI application analysis:",
            f"  application files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: routes={info.route_decorators}, "
                f"cors={info.has_cors}, trusted_host={info.has_trusted_host}, "
                f"rate_limit={info.has_rate_limit}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
