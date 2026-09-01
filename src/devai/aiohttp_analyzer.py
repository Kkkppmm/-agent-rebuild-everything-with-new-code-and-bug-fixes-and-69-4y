"""AiohttpAnalyzer — audit aiohttp apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

AIOHTTP_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
    "app/server.py",
)
AIOHTTP_IMPORT_PATTERN = re.compile(
    r"(?:from\s+aiohttp|import\s+aiohttp|web\.Application\s*\()",
    re.IGNORECASE,
)
AIOHTTP_ROUTE_PATTERN = re.compile(
    r"(?:app\.router\.add_(?:get|post|put|delete|patch)|"
    r"@routes\.(?:get|post|put|delete|patch)|"
    r"web\.(?:get|post|put|delete|patch)\s*\()",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:aiohttp_cors|CORS)\s*\([^)]*origins\s*=\s*['\"]\*['\"]|"
    r"origins\s*=\s*['\"]\*['\"]|"
    r"defaults\s*=\s*\{[^}]*['\"]\*['\"]\s*:",
    re.IGNORECASE | re.DOTALL,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True[\s\S]{0,120}origins\s*=\s*['\"]\*['\"]|"
    r"origins\s*=\s*['\"]\*['\"][\s\S]{0,120}allow_credentials\s*=\s*True|"
    r"['\"]\*['\"]\s*:\s*aiohttp_cors\.ResourceOptions\([^)]*allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify_ssl\s*=\s*False|ssl\s*=\s*False|connector\s*=\s*.*ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:session|ClientSession)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"web\.run_app\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"debug\s*=\s*True",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"(?:add_(?:get|post|put|delete|patch)|@routes\.(?:get|post))\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
SHELL_COMMAND_PATTERN = re.compile(
    r"(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|asyncio\.create_subprocess_shell)\s*\(",
    re.IGNORECASE,
)
FILE_RESPONSE_PATTERN = re.compile(
    r"web\.FileResponse\s*\([^)]*request\.|"
    r"web\.FileResponse\s*\(\s*request\.",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)


@dataclass
class AiohttpFinding:
    """A security or best-practice issue in an aiohttp application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class AiohttpInfo:
    """Parsed metadata about an aiohttp application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_session: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class AiohttpStats:
    """Aggregate aiohttp analysis statistics."""

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


def _contains_aiohttp(text: str) -> bool:
    return bool(
        AIOHTTP_IMPORT_PATTERN.search(text)
        or AIOHTTP_ROUTE_PATTERN.search(text)
        or "web.Application(" in text
    )


def _looks_like_aiohttp_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "aiohttp" in text:
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
            if any("aiohttp" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in AIOHTTP_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_aiohttp(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class AiohttpAnalyzer:
    """Audit aiohttp applications for security and production risks.

    Scans aiohttp entry files, routes, and middleware for hardcoded secrets,
    open CORS, debug mode, disabled TLS verification, SSRF targets, shell commands,
    and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AiohttpFinding] | None = None
        self._stats: AiohttpStats | None = None
        self._infos: list[AiohttpInfo] | None = None

    def configs(self) -> list[Path]:
        """Return aiohttp application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in AIOHTTP_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_aiohttp(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_aiohttp_project(self.root):
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
                if _contains_aiohttp(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[AiohttpFinding],
        info: AiohttpInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"(?:add_(?:get|post|put|delete|patch)|@routes\.(?:get|post))\s*\(\s*['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if route_match:
            route = route_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        if "aiohttp_cors" in stripped.lower() or "CORS(" in stripped:
            info.has_cors = True
        if any(k in stripped for k in ("aiohttp_session", "SessionMiddleware", "login_required")):
            info.has_session = True
        if any(k in stripped for k in ("BasicAuth", "jwt_required", "authorized")):
            info.has_auth = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in aiohttp app — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in aiohttp app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in aiohttp app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS origins includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in aiohttp app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "aiohttp bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid subprocess with user input"),
            (FILE_RESPONSE_PATTERN, "path_traversal_file_response", "high",
             "FileResponse with request data — validate paths to prevent traversal"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    AiohttpFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[AiohttpFinding], AiohttpInfo]:
        findings: list[AiohttpFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, AiohttpInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = AiohttpInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    AiohttpFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[AiohttpFinding]:
        """Scan aiohttp application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AiohttpFinding] = []
        infos: list[AiohttpInfo] = []
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
        self._stats = AiohttpStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AiohttpStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AiohttpInfo]:
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
        """Scaffold a hardened aiohttp main.py entry template."""
        return """\
# Generated by DevAI AiohttpAnalyzer
import os

from aiohttp import web
import aiohttp_cors


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def create_app() -> web.Application:
    app = web.Application()
    cors = aiohttp_cors.setup(
        app,
        defaults={
            origin: aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
            for origin in os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(",")
        },
    )
    app.router.add_get("/health", health)
    for route in list(app.router.routes()):
        cors.add(route)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="127.0.0.1", port=8080)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "aiohttp: no application files found"
        return (
            f"aiohttp: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "aiohttp application analysis:",
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
