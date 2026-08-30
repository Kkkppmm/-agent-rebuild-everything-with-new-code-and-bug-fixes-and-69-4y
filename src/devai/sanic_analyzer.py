"""SanicAnalyzer — audit Sanic apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

SANIC_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "asgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
)
SANIC_IMPORT_PATTERN = re.compile(
    r"(?:from\s+sanic|import\s+sanic|Sanic\s*\()",
    re.IGNORECASE,
)
SANIC_ROUTE_PATTERN = re.compile(
    r"@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch)\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|SECRET)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
APP_CONFIG_SECRET_PATTERN = re.compile(
    r"app\.config\.(?:SECRET|SECRET_KEY|JWT_SECRET|API_KEY)\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:CORS\s*\([^)]*origins\s*=\s*['\"]\*['\"]|"
    r"['\"]origins['\"]\s*:\s*['\"]\*['\"]|"
    r"origins\s*=\s*['\"]\*['\"]|"
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"])",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"supports_credentials\s*=\s*True[\s\S]{0,120}(?:['\"]origins['\"]\s*:\s*['\"]\*['\"]|origins\s*=\s*['\"]\*['\"])|"
    r"(?:['\"]origins['\"]\s*:\s*['\"]\*['\"]|origins\s*=\s*['\"]\*['\"])[\s\S]{0,120}supports_credentials\s*=\s*True|"
    r"allow_credentials\s*=\s*True[\s\S]{0,120}(?:['\"]origins['\"]\s*:\s*['\"]\*['\"]|origins\s*=\s*['\"]\*['\"])",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False|verify_ssl\s*=\s*False",
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
    r"app\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:app\.run\s*\([^)]*)?debug\s*=\s*True|"
    r"app\.config\.DEBUG\s*=\s*True|"
    r"DEBUG\s*=\s*True",
    re.IGNORECASE,
)
SSTI_PATTERN = re.compile(
    r"(?:render_template_string|Environment\s*\(\s*\)\.from_string)\s*\(",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)


@dataclass
class SanicFinding:
    """A security or best-practice issue in a Sanic application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class SanicInfo:
    """Parsed metadata about a Sanic application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_https_redirect: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class SanicStats:
    """Aggregate Sanic analysis statistics."""

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


def _contains_sanic(text: str) -> bool:
    return bool(
        SANIC_IMPORT_PATTERN.search(text)
        or SANIC_ROUTE_PATTERN.search(text)
        or "Sanic(" in text
    )


def _looks_like_sanic_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "sanic" in text:
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
            if any("sanic" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in SANIC_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_sanic(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class SanicAnalyzer:
    """Audit Sanic applications for security and production risks.

    Scans Sanic entry files, routes, and middleware for hardcoded secrets,
    open CORS, debug mode, SSTI via template rendering, SSRF targets,
    and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SanicFinding] | None = None
        self._stats: SanicStats | None = None
        self._infos: list[SanicInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Sanic application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in SANIC_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_sanic(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_sanic_project(self.root):
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
                if _contains_sanic(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SanicFinding],
        info: SanicInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for route_kw in ("@app.route", "@app.get", "@app.post", "@bp.route", "@bp.get"):
            if route_kw in stripped:
                if route_kw not in info.routes:
                    info.routes.append(route_kw)

        if "CORS" in stripped or "cors" in stripped.lower() or "sanic_ext" in stripped:
            info.has_cors = True
        if any(k in stripped for k in ("login_required", "authorized", "check_auth")):
            info.has_auth = True
        if "HTTPSRedirect" in stripped or "force_https" in stripped:
            info.has_https_redirect = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Sanic app — use environment variables"),
            (APP_CONFIG_SECRET_PATTERN, "app_config_secret", "high",
             "hardcoded app.config secret — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Sanic app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Sanic app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Sanic app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "Sanic bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (SSTI_PATTERN, "ssti", "high",
             "template rendering with user input — SSTI risk, use safe templates"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    SanicFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[SanicFinding], SanicInfo]:
        findings: list[SanicFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, SanicInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = SanicInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if APP_CONFIG_SECRET_PATTERN.search(raw_text):
            if not any(f.kind == "app_config_secret" for f in findings):
                findings.append(
                    SanicFinding(
                        kind="app_config_secret",
                        severity="high",
                        message="hardcoded app.config secret — use environment variables",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    SanicFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[SanicFinding]:
        """Scan Sanic application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SanicFinding] = []
        infos: list[SanicInfo] = []
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
        self._stats = SanicStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SanicStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SanicInfo]:
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
        """Scaffold a hardened Sanic main.py entry template."""
        return """\
# Generated by DevAI SanicAnalyzer
import os

from sanic import Sanic, response
from sanic_ext import Extend, cors


def create_app() -> Sanic:
    app = Sanic(__name__)
    app.config.SECRET = os.environ["SECRET_KEY"]
    app.config.DEBUG = False

    Extend(app)
    cors(
        app,
        resources={
            r"/*": {
                "origins": os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
                "supports_credentials": True,
            }
        },
    )

    @app.get("/health")
    async def health(request):
        return response.json({"status": "ok"})

    return app


app = create_app()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Sanic: no application files found"
        return (
            f"Sanic: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Sanic application analysis:",
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
