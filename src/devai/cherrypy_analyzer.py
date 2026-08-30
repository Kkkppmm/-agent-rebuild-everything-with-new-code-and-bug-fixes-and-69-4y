"""CherryPyAnalyzer — audit CherryPy apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CHERRYPY_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "wsgi.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
)
CHERRYPY_IMPORT_PATTERN = re.compile(
    r"(?:from\s+cherrypy|import\s+cherrypy|cherrypy\.(?:quickstart|tree|config))",
    re.IGNORECASE,
)
CHERRYPY_EXPOSE_PATTERN = re.compile(
    r"@cherrypy\.expose|cherrypy\.expose\s*\(",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|tools\.sessions\.secret)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
SESSION_SECRET_PATTERN = re.compile(
    r"tools\.sessions\.secret\s*[=:]\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]|"
    r"allow_origin\s*[=:]\s*['\"]\*['\"]|"
    r"origins\s*[=:]\s*['\"]\*['\"])",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Credentials['\"]\s*,\s*['\"]true['\"][\s\S]{0,120}"
    r"Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]|"
    r"Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"][\s\S]{0,120}"
    r"Access-Control-Allow-Credentials['\"]\s*,\s*['\"]true['\"]",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"['\"]?tools\.xsrf(?:\.on)?['\"]?\s*[=:]\s*False|"
    r"['\"]?tools\.xsrf_protection['\"]?\s*[=:]\s*False",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False|"
    r"server\.ssl_module\s*[=:]\s*None",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*[=:]\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|urllib|httpx)\.(?:get|post|request|urlopen)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"server\.socket_host\s*[=:]\s*['\"]0\.0\.0\.0['\"]|"
    r"host\s*[=:]\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"engine\.autoreload\.on\s*[=:]\s*True|"
    r"environment\s*[=:]\s*['\"]development['\"]|"
    r"cherrypy\.config\.update\s*\([^)]*debug\s*[=:]\s*True",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@cherrypy\.expose(?:\(\s*['\"](?:/)?(?:admin|debug|internal)|"
    r"\s*\n\s*def\s+(?:admin|debug|internal)_\w+)|"
    r"def\s+(?:admin|debug|internal)_\w+\s*\(",
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
PATH_TRAVERSAL_PATTERN = re.compile(
    r"tools\.static(?:dir|file)\s*[=:][\s\S]{0,80}(?:request\.|params\.|querystring)",
    re.IGNORECASE,
)
AUTH_BASIC_HARDCODED_PATTERN = re.compile(
    r"tools\.auth_basic\.(?:users|checkpassword)\s*[=:][\s\S]{0,120}['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
SESSION_INSECURE_PATTERN = re.compile(
    r"tools\.sessions\.(?:httponly|secure)\s*[=:]\s*False",
    re.IGNORECASE,
)
COOKIE_SAMESITE_NONE_PATTERN = re.compile(
    r"tools\.sessions\.samesite\s*[=:]\s*['\"]none['\"]",
    re.IGNORECASE,
)


@dataclass
class CherryPyFinding:
    """A security or best-practice issue in a CherryPy application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CherryPyInfo:
    """Parsed metadata about a CherryPy application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_sessions: bool = False
    has_xsrf: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class CherryPyStats:
    """Aggregate CherryPy analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in (".toml", ".json", ".yaml", ".yml", ".conf", ".ini"):
        return path.suffix.lstrip(".")
    return "unknown"


def _contains_cherrypy(text: str) -> bool:
    return bool(
        CHERRYPY_IMPORT_PATTERN.search(text)
        or CHERRYPY_EXPOSE_PATTERN.search(text)
        or "cherrypy.quickstart" in text
    )


def _looks_like_cherrypy_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "cherrypy" in text:
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
            if any("cherrypy" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in CHERRYPY_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_cherrypy(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class CherryPyAnalyzer:
    """Audit CherryPy applications for security and production risks.

    Scans CherryPy entry files and config for hardcoded session secrets,
    disabled XSRF protection, open CORS, dev mode/autoreload, SSRF targets,
    shell command execution, path traversal in static handlers, and
    unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CherryPyFinding] | None = None
        self._stats: CherryPyStats | None = None
        self._infos: list[CherryPyInfo] | None = None

    def configs(self) -> list[Path]:
        """Return CherryPy application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in CHERRYPY_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_cherrypy(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_cherrypy_project(self.root):
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
                if _contains_cherrypy(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CherryPyFinding],
        info: CherryPyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        expose_match = re.search(
            r"@cherrypy\.expose(?:\(\s*['\"]([^'\"]+)['\"])?",
            stripped,
            re.IGNORECASE,
        )
        if expose_match and expose_match.group(1):
            route = expose_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        func_match = re.search(
            r"def\s+((?:admin|debug|internal)_\w+)\s*\(",
            stripped,
            re.IGNORECASE,
        )
        if func_match:
            route = func_match.group(1)
            if route not in info.routes:
                info.routes.append(route)
            if re.match(r"(?:admin|debug|internal)_", route, re.IGNORECASE):
                findings.append(
                    CherryPyFinding(
                        kind="dangerous_route",
                        severity="high",
                        message="admin/debug/internal route — ensure authentication is required",
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

        if any(k in stripped.lower() for k in ("access-control-allow-origin", "cors")):
            info.has_cors = True
        if any(k in stripped for k in ("tools.auth_basic", "tools.auth_digest")):
            info.has_auth = True
        if "tools.sessions.on" in stripped or "tools.sessions.timeout" in stripped:
            info.has_sessions = True
        if "tools.xsrf" in stripped:
            info.has_xsrf = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in CherryPy app — use environment variables or config files"),
            (SESSION_SECRET_PATTERN, "session_secret", "high",
             "hardcoded tools.sessions.secret — load from environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in CherryPy app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in CherryPy app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allows '*' origin — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled — enable tools.xsrf.on in production"),
            (AUTH_BASIC_HARDCODED_PATTERN, "auth_basic_hardcoded", "high",
             "hardcoded credentials in tools.auth_basic — use secure credential stores"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification or SSL module disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in CherryPy app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "CherryPy bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (DEBUG_MODE_PATTERN, "dev_mode", "medium",
             "development mode or autoreload enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (PATH_TRAVERSAL_PATTERN, "path_traversal_static", "high",
             "static handler uses request data — validate paths to prevent traversal"),
            (SESSION_INSECURE_PATTERN, "session_insecure", "medium",
             "session cookie secure/httponly disabled — enable in production"),
            (COOKIE_SAMESITE_NONE_PATTERN, "cookie_samesite_none", "medium",
             "session cookie samesite='none' — ensure tools.sessions.secure=True"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    CherryPyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[CherryPyFinding], CherryPyInfo]:
        findings: list[CherryPyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CherryPyInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = CherryPyInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    CherryPyFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[CherryPyFinding]:
        """Scan CherryPy application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CherryPyFinding] = []
        infos: list[CherryPyInfo] = []
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
        self._stats = CherryPyStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CherryPyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CherryPyInfo]:
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
        """Scaffold a hardened CherryPy app.py entry template."""
        return """\
# Generated by DevAI CherryPyAnalyzer
import os

import cherrypy


class Root:
    @cherrypy.expose
    def index(self) -> str:
        return "ok"

    @cherrypy.expose
    def health(self) -> dict[str, str]:
        return {"status": "ok"}


def create_app() -> None:
    cherrypy.config.update({
        "server.socket_host": os.environ.get("HOST", "127.0.0.1"),
        "server.socket_port": int(os.environ.get("PORT", "8080")),
        "engine.autoreload.on": False,
        "environment": "production",
        "tools.sessions.on": True,
        "tools.sessions.secret": os.environ["SESSION_SECRET"],
        "tools.sessions.httponly": True,
        "tools.sessions.secure": True,
        "tools.sessions.samesite": "Lax",
        "tools.xsrf.on": True,
    })


if __name__ == "__main__":
    create_app()
    cherrypy.quickstart(Root())
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "CherryPy: no application files found"
        return (
            f"CherryPy: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "CherryPy application analysis:",
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
