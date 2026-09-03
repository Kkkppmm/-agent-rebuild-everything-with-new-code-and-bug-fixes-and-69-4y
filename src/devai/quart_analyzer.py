"""QuartAnalyzer — audit Quart apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

QUART_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "asgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
    "app/__init__.py",
)
QUART_IMPORT_PATTERN = re.compile(
    r"(?:from\s+quart|import\s+quart|Quart\s*\()",
    re.IGNORECASE,
)
QUART_ROUTE_PATTERN = re.compile(
    r"@(?:app|bp|blueprint|(?:\w+_)?bp)\.(?:route|get|post|put|delete|patch|websocket)\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|SECRET_KEY)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
APP_CONFIG_SECRET_PATTERN = re.compile(
    r"app\.config\s*\[\s*['\"](?:SECRET_KEY|JWT_SECRET_KEY|API_KEY)['\"]\s*\]\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:quart_cors\s*\(|CORS\s*\()[^)]*(?:origins|allow_origin)\s*=\s*['\"]\*['\"]|"
    r"(?:origins|allow_origin)\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True[\s\S]{0,120}origins\s*=\s*['\"]\*['\"]|"
    r"origins\s*=\s*['\"]\*['\"][\s\S]{0,120}allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_SECURE|REMEMBER_COOKIE_SECURE)\s*=\s*False",
    re.IGNORECASE,
)
COOKIE_HTTPONLY_FALSE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_HTTPONLY|REMEMBER_COOKIE_HTTPONLY)\s*=\s*False",
    re.IGNORECASE,
)
SAME_SITE_NONE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_SAMESITE|REMEMBER_COOKIE_SAMESITE)\s*=\s*['\"]None['\"]",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False|verify_ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:httpx|aiohttp)\.(?:get|post|request|ClientSession)\s*\([^)]*['\"]https?://(?:10\.|"
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
    r"(?:app\.run\s*\([^)]*)?(?:debug|DEBUG)\s*=\s*True|"
    r"app\.config\s*\[\s*['\"]DEBUG['\"]\s*\]\s*=\s*True",
    re.IGNORECASE,
)
SSTI_PATTERN = re.compile(
    r"render_template_string\s*\(",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch|websocket)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
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
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|asyncio\.create_subprocess_shell)\s*\(",
    re.IGNORECASE,
)
SEND_FILE_PATTERN = re.compile(
    r"send_file\s*\([^)]*(?:request\.|request\.args|request\.form)",
    re.IGNORECASE,
)
PERMANENT_SESSION_PATTERN = re.compile(
    r"PERMANENT_SESSION_LIFETIME\s*=\s*(?:timedelta\s*\(\s*days\s*=\s*\d{2,}|86400\s*\*\s*\d{2,})",
    re.IGNORECASE,
)
TALISMAN_DISABLED_PATTERN = re.compile(
    r"Talisman\s*\([^)]*force_https\s*=\s*False",
    re.IGNORECASE,
)


@dataclass
class QuartFinding:
    """A security or best-practice issue in a Quart application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class QuartInfo:
    """Parsed metadata about a Quart application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_talisman: bool = False
    has_blueprint: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class QuartStats:
    """Aggregate Quart analysis statistics."""

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


def _contains_quart(text: str) -> bool:
    return bool(
        QUART_IMPORT_PATTERN.search(text)
        or QUART_ROUTE_PATTERN.search(text)
        or "Quart(" in text
    )


def _looks_like_quart_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "quart" in text:
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
            if any("quart" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in QUART_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_quart(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class QuartAnalyzer:
    """Audit Quart applications for security and production risks.

    Scans Quart entry files, blueprints, and config for hardcoded secrets,
    open CORS, debug mode, SSTI via render_template_string, SSRF targets,
    shell command execution, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[QuartFinding] | None = None
        self._stats: QuartStats | None = None
        self._infos: list[QuartInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Quart application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in QUART_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_quart(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_quart_project(self.root):
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
                if _contains_quart(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[QuartFinding],
        info: QuartInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch|websocket)\s*\(\s*['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if route_match:
            route = route_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        if "CORS(" in stripped or "quart_cors" in stripped.lower():
            info.has_cors = True
        if any(k in stripped for k in ("login_required", "jwt_required", "HTTPBasicAuth", "verify_jwt")):
            info.has_auth = True
        if "Talisman(" in stripped:
            info.has_talisman = True
        if "Blueprint(" in stripped:
            info.has_blueprint = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Quart app — use environment variables or config classes"),
            (APP_CONFIG_SECRET_PATTERN, "app_config_secret", "high",
             "hardcoded secret in app.config — load from environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Quart app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Quart app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "session cookie secure=False — set SESSION_COOKIE_SECURE=True in production"),
            (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
             "session cookie httponly=False — enable SESSION_COOKIE_HTTPONLY"),
            (SAME_SITE_NONE_PATTERN, "cookie_samesite_none", "medium",
             "session cookie samesite='None' — ensure SESSION_COOKIE_SECURE=True"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Quart app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "Quart bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (SSTI_PATTERN, "ssti_risk", "high",
             "render_template_string() — SSTI risk; use render_template with static files"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (SEND_FILE_PATTERN, "path_traversal_send_file", "high",
             "send_file with request data — validate paths to prevent traversal"),
            (PERMANENT_SESSION_PATTERN, "long_session_lifetime", "low",
             "very long session lifetime — review PERMANENT_SESSION_LIFETIME"),
            (TALISMAN_DISABLED_PATTERN, "talisman_https_disabled", "medium",
             "Quart-Talisman force_https=False — enable HTTPS redirect in production"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    QuartFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[QuartFinding], QuartInfo]:
        findings: list[QuartFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, QuartInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = QuartInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    QuartFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[QuartFinding]:
        """Scan Quart application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[QuartFinding] = []
        infos: list[QuartInfo] = []
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
        self._stats = QuartStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> QuartStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[QuartInfo]:
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
        """Scaffold a hardened Quart app.py entry template."""
        return """\
# Generated by DevAI QuartAnalyzer
import os

from quart import Quart
from quart_talisman import Talisman
from quart_cors import cors


def create_app() -> Quart:
    app = Quart(__name__)
    app.config.update(
        SECRET_KEY=os.environ["SECRET_KEY"],
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        DEBUG=False,
    )

    Talisman(app, force_https=True)
    cors(
        app,
        allow_origin=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
        allow_credentials=True,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Quart: no application files found"
        return (
            f"Quart: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Quart application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"routes={','.join(info.routes[:5]) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
