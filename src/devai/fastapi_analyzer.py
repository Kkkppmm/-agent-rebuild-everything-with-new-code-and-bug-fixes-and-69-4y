"""FastAPIAnalyzer — audit FastAPI apps for secrets, CORS, docs exposure, and SSRF risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FASTAPI_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "asgi.py",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:SECRET|API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL|CLIENT[_-]?SECRET)\s*[=:]\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
HARDCODED_SECRET_CONFIG_PATTERN = re.compile(
    r"(?:SECRET|API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL|CLIENT[_-]?SECRET)['\"]?\s*[=:]\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_ALLOW_ALL_PATTERN = re.compile(
    r"allow_origin_regex\s*=\s*['\"].*\*.*['\"]",
    re.IGNORECASE,
)
DOCS_EXPOSED_PATTERN = re.compile(
    r"(?:docs_url|redoc_url|openapi_url)\s*=\s*(?!None\b)[\"']/[^\"']+[\"']\s*,?\s*$",
    re.IGNORECASE,
)
DEBUG_UVICORN_PATTERN = re.compile(
    r"uvicorn\.run\s*\([^)]*reload\s*=\s*True",
    re.IGNORECASE | re.DOTALL,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
    re.IGNORECASE,
)
INTERNAL_SSRF_PATTERN = re.compile(
    r"['\"]https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)[^'\"]+['\"]",
    re.IGNORECASE,
)
TLS_VERIFY_DISABLED_PATTERN = re.compile(
    r"verify\s*=\s*False",
    re.IGNORECASE,
)
TRUSTED_HOST_WILDCARD_PATTERN = re.compile(
    r"allowed_hosts\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
FASTAPI_IMPORT_PATTERN = re.compile(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b|FastAPI\s*\(")


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
    has_middleware: bool = False
    has_router: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class FastAPIStats:
    """Aggregate FastAPI analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_fastapi_file(path: Path, content: str | None = None) -> bool:
    if path.name in FASTAPI_ENTRY_NAMES:
        return True
    if path.suffix != ".py":
        return False
    if content is None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(FASTAPI_IMPORT_PATTERN.search(content))


def _looks_like_fastapi_project(root: Path) -> bool:
    for name in FASTAPI_ENTRY_NAMES:
        if (root / name).is_file():
            return True
    pkg = root / "pyproject.toml"
    req = root / "requirements.txt"
    for path in (pkg, req):
        if path.is_file() and "fastapi" in path.read_text(encoding="utf-8", errors="replace").lower():
            return True
    return False


class FastAPIAnalyzer:
    """Audit FastAPI applications for open CORS, exposed docs, secrets, and SSRF risks.

    Scans main.py, app.py, and FastAPI entrypoints for hardcoded credentials,
    permissive CORS, production API docs exposure, TLS verification bypass,
    and internal proxy/redirect targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FastAPIFinding] | None = None
        self._stats: FastAPIStats | None = None
        self._infos: list[FastAPIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return FastAPI application paths found in the project."""
        found: list[Path] = []
        for name in FASTAPI_ENTRY_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*.py")):
            if path in found or "site-packages" in path.parts or ".venv" in path.parts:
                continue
            if _is_fastapi_file(path):
                found.append(path)
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

        for section in ("CORSMiddleware", "add_middleware", "APIRouter", "include_router"):
            if section in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "CORSMiddleware":
                    info.has_cors = True
                elif section in ("add_middleware",):
                    info.has_middleware = True
                elif section in ("APIRouter", "include_router"):
                    info.has_router = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in FastAPI app — use environment variables"),
            (HARDCODED_SECRET_CONFIG_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in FastAPI app — use environment variables"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins=['*'] — any origin may call the API"),
            (INTERNAL_SSRF_PATTERN, "internal_url", "high",
             "URL targets internal IP — SSRF risk in proxies or webhooks"),
            (TLS_VERIFY_DISABLED_PATTERN, "tls_verification_disabled", "high",
             "TLS certificate verification disabled — man-in-the-middle risk"),
            (CORS_ALLOW_ALL_PATTERN, "cors_regex_wildcard", "medium",
             "CORS allow_origin_regex is permissive — restrict trusted origins"),
            (DOCS_EXPOSED_PATTERN, "docs_exposed", "medium",
             "API docs/redoc/openapi URLs enabled — disable in production"),
            (DEBUG_UVICORN_PATTERN, "uvicorn_reload", "medium",
             "uvicorn reload=True — development mode should not run in production"),
            (TRUSTED_HOST_WILDCARD_PATTERN, "trusted_host_wildcard", "medium",
             "allowed_hosts=['*'] — Host header validation disabled"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "low",
             "HTTP URL in FastAPI app — prefer HTTPS for external services"),
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
        """Scaffold a hardened FastAPI application template."""
        return """\
# Generated by DevAI FastAPIAnalyzer
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

DEBUG = os.environ.get("FASTAPI_DEBUG", "false").lower() == "true"

app = FastAPI(
    title="My API",
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)
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
            f"  application files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: sections={','.join(info.sections) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
