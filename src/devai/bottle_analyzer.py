"""BottleAnalyzer — audit Bottle apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

BOTTLE_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "wsgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
)
BOTTLE_IMPORT_PATTERN = re.compile(
    r"(?:from\s+bottle|import\s+bottle|Bottle\s*\()",
    re.IGNORECASE,
)
BOTTLE_ROUTE_PATTERN = re.compile(
    r"@(?:app\.)?(?:route|get|post|put|delete|patch|hook)\s*\(",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|SECRET_KEY)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:origins\s*=\s*['\"]\*['\"]|"
    r"Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]|"
    r"allow_origin\s*=\s*['\"]\*['\"])",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|urllib|httpx)\.(?:get|post|request|urlopen)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:bottle\.)?run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:bottle\.)?run\s*\([^)]*debug\s*=\s*True|"
    r"(?:^|\s)debug\s*=\s*True",
    re.IGNORECASE,
)
RELOADER_PATTERN = re.compile(
    r"reloader\s*=\s*True",
    re.IGNORECASE,
)
TEMPLATE_SSTI_PATTERN = re.compile(
    r"(?:template|SimpleTemplate|stpl)\s*\(",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@(?:app\.)?(?:route|get|post|put|delete|patch)\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
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
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    re.IGNORECASE,
)
STATIC_FILE_PATTERN = re.compile(
    r"static_file\s*\([^)]*(?:request\.|query\.|params\.|forms\.|GET\.|POST\.)",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:secure|httponly)\s*=\s*False",
    re.IGNORECASE,
)
PLUGIN_AUTH_PATTERN = re.compile(
    r"(?:BasicAuth|AuthBasic|auth_basic)\s*\(",
    re.IGNORECASE,
)


@dataclass
class BottleFinding:
    """A security or best-practice issue in a Bottle application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BottleInfo:
    """Parsed metadata about a Bottle application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_plugin: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class BottleStats:
    """Aggregate Bottle analysis statistics."""

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


def _contains_bottle(text: str) -> bool:
    return bool(
        BOTTLE_IMPORT_PATTERN.search(text)
        or BOTTLE_ROUTE_PATTERN.search(text)
        or "Bottle(" in text
    )


def _looks_like_bottle_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "bottle" in text:
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
            if any("bottle" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in BOTTLE_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_bottle(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class BottleAnalyzer:
    """Audit Bottle applications for security and production risks.

    Scans Bottle entry files and plugins for hardcoded secrets, debug mode,
    SSTI via template(), path traversal in static_file(), SSRF targets,
    shell command execution, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BottleFinding] | None = None
        self._stats: BottleStats | None = None
        self._infos: list[BottleInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bottle application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in BOTTLE_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_bottle(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_bottle_project(self.root):
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
                if _contains_bottle(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BottleFinding],
        info: BottleInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"@(?:app\.)?(?:route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if route_match:
            route = route_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        if any(k in stripped.lower() for k in ("cors", "allow_origin", "access-control")):
            info.has_cors = True
        if PLUGIN_AUTH_PATTERN.search(stripped):
            info.has_auth = True
        if ".install(" in stripped or "Plugin" in stripped:
            info.has_plugin = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Bottle app — use environment variables or config"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Bottle app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Bottle app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS origins includes '*' — restrict to trusted origins"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "cookie secure/httponly=False — enable secure cookie flags in production"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Bottle app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "Bottle bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (RELOADER_PATTERN, "reloader_enabled", "medium",
             "reloader=True — disable in production; exposes code execution risk"),
            (TEMPLATE_SSTI_PATTERN, "ssti_risk", "high",
             "template()/SimpleTemplate() — SSTI risk; avoid user-controlled templates"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (STATIC_FILE_PATTERN, "path_traversal_static_file", "high",
             "static_file with request data — validate paths to prevent traversal"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    BottleFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[BottleFinding], BottleInfo]:
        findings: list[BottleFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BottleInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = BottleInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[BottleFinding]:
        """Scan Bottle application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BottleFinding] = []
        infos: list[BottleInfo] = []
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
        self._stats = BottleStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BottleStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BottleInfo]:
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
        """Scaffold a hardened Bottle app.py entry template."""
        return """\
# Generated by DevAI BottleAnalyzer
import os

from bottle import Bottle, run, request, response
from beaker.middleware import SessionMiddleware


def create_app() -> Bottle:
    app = Bottle()

    @app.hook("after_request")
    def set_security_headers():
        response.set_header("X-Content-Type-Options", "nosniff")
        response.set_header("X-Frame-Options", "DENY")
        response.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
session_app = SessionMiddleware(
    app,
    {"session.cookie_expires": 3600, "session.secure": True, "session.httponly": True},
)


if __name__ == "__main__":
    run(
        session_app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        debug=False,
        reloader=False,
    )
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bottle: no application files found"
        return (
            f"Bottle: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Bottle application analysis:",
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
