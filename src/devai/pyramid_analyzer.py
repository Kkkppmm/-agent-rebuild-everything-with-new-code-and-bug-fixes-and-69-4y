"""PyramidAnalyzer — audit Pyramid apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PYRAMID_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "wsgi.py",
    "application.py",
    "src/main.py",
    "src/app.py",
    "src/wsgi.py",
    "app/main.py",
    "app/__init__.py",
    "development.ini",
    "production.ini",
    "testing.ini",
)
PYRAMID_IMPORT_PATTERN = re.compile(
    r"(?:from\s+pyramid(?:\.\w+)?\s+import|import\s+pyramid|"
    r"pyramid\.config\.Configurator|@view_config|config\.add_route)",
    re.IGNORECASE,
)
PYRAMID_ROUTE_PATTERN = re.compile(
    r"(?:@view_config|config\.add_route|add_route)\s*\(",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|auth_tkt\.secret)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Origin|allow_origin|allow_origins)\s*[=:]\s*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"(?:Access-Control-Allow-Credentials|allow_credentials)\s*[=:]\s*(?:True|true|['\"]true['\"])"
    r"[\s\S]{0,120}(?:Access-Control-Allow-Origin|allow_origin|allow_origins)\s*[=:]\s*['\"]\*['\"]|"
    r"(?:Access-Control-Allow-Origin|allow_origin|allow_origins)\s*[=:]\s*['\"]\*['\"]"
    r"[\s\S]{0,120}(?:Access-Control-Allow-Credentials|allow_credentials)\s*[=:]\s*(?:True|true|['\"]true['\"])",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*[=:]\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:urllib|requests|httpx|aiohttp)\.(?:urlopen|get|post|request)\s*\([^)]*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:pyramid\.reload_templates|reload_templates)\s*=\s*true|"
    r"debug_authorization\s*=\s*true|"
    r"pyramid\.debug_authorization\s*=\s*true",
    re.IGNORECASE,
)
DEBUG_TOOLBAR_PATTERN = re.compile(
    r"(?:include|config\.include)\s*\(\s*['\"]pyramid_debugtoolbar['\"]|"
    r"pyramid\.includes\s*=\s*[^\n]*pyramid_debugtoolbar",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"(?:@view_config|add_route)\s*\([^)]*(?:admin|debug|internal)",
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
CSRF_DISABLED_PATTERN = re.compile(
    r"(?:csrf(?:\.\w+)?|enable_csrf|require_csrf)\s*[=:]\s*(?:False|false|0|off)",
    re.IGNORECASE,
)
INSECURE_SESSION_PATTERN = re.compile(
    r"(?:session\.secure|session\.httponly)\s*=\s*(?:false|False|0)",
    re.IGNORECASE,
)
SSTI_PATTERN = re.compile(
    r"(?:render_to_response|render)\s*\([^)]*(?:request\.|\.params|\.GET|\.POST|\.matchdict)",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"(?:HTTPFound|HTTPMovedPermanently|HTTPFound)\s*\(\s*(?:request\.|\.params|\.GET)",
    re.IGNORECASE,
)
AUTH_ALLOW_ALL_PATTERN = re.compile(
    r"(?:Allow|ACLAllow)\s*\([^)]*['\"]Everyone['\"]",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:host|bind)\s*=\s*['\"]0\.0\.0\.0['\"]|listen\s*=\s*0\.0\.0\.0",
    re.IGNORECASE,
)


@dataclass
class PyramidFinding:
    """A security or best-practice issue in a Pyramid application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PyramidInfo:
    """Parsed metadata about a Pyramid application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_debug: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class PyramidStats:
    """Aggregate Pyramid analysis statistics."""

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


def _contains_pyramid(text: str) -> bool:
    return bool(
        PYRAMID_IMPORT_PATTERN.search(text)
        or PYRAMID_ROUTE_PATTERN.search(text)
        or "Configurator(" in text
        or "pyramid.includes" in text
        or "pyramid." in text
        or re.search(r"\[app:main\]", text, re.IGNORECASE)
    )


def _looks_like_pyramid_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.cfg"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "pyramid" in text:
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
            if any("pyramid" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in PYRAMID_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_pyramid(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class PyramidAnalyzer:
    """Audit Pyramid applications for security and production risks.

    Scans Pyramid entry files, view configs, and ini settings for hardcoded
    secrets, debug toolbar, disabled CSRF, permissive ACLs, SSRF targets,
    shell command execution, SSTI, and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PyramidFinding] | None = None
        self._stats: PyramidStats | None = None
        self._infos: list[PyramidInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Pyramid application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in PYRAMID_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_pyramid(text) or (
                    path.suffix == ".ini" and _looks_like_pyramid_project(self.root)
                ):
                    found.append(path)
                    seen.add(path)

        if _looks_like_pyramid_project(self.root):
            for path in sorted(self.root.rglob("*")):
                if not path.is_file() or path in seen:
                    continue
                if path.suffix not in (".py", ".ini", ".cfg"):
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
                if _contains_pyramid(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PyramidFinding],
        info: PyramidInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            return

        route_match = re.search(
            r"(?:@view_config|add_route)\s*\([^)]*route_name\s*=\s*['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if not route_match:
            route_match = re.search(
                r"(?:@view_config|add_route)\s*\(\s*['\"]([^'\"]+)['\"]",
                stripped,
                re.IGNORECASE,
            )
        if route_match and route_match.group(1) not in info.routes:
            info.routes.append(route_match.group(1))

        if "Access-Control-Allow-Origin" in stripped or "allow_origin" in stripped:
            info.has_cors = True
        if "reload_templates" in stripped or "debug_authorization" in stripped:
            info.has_debug = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Pyramid app — use environment variables or ini overrides"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Pyramid app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Pyramid app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS Access-Control-Allow-Origin includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Pyramid app — avoid dynamic code execution"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug settings enabled — disable in production"),
            (DEBUG_TOOLBAR_PATTERN, "debug_toolbar", "high",
             "pyramid_debugtoolbar included — remove from production deployments"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal endpoint — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (CSRF_DISABLED_PATTERN, "csrf_disabled", "high",
             "CSRF protection disabled — enable CSRF for state-changing requests"),
            (INSECURE_SESSION_PATTERN, "insecure_session", "high",
             "session cookie missing secure/httponly flags"),
            (SSTI_PATTERN, "ssti", "high",
             "template render with user input — validate or use autoescaping to prevent SSTI"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "high",
             "redirect with user-controlled URL — validate redirect targets"),
            (AUTH_ALLOW_ALL_PATTERN, "auth_allow_all", "high",
             "ACL allows Everyone — restrict to authenticated principals"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "Pyramid bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    PyramidFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[PyramidFinding], PyramidInfo]:
        findings: list[PyramidFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PyramidInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = PyramidInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    PyramidFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[PyramidFinding]:
        """Scan Pyramid application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PyramidFinding] = []
        infos: list[PyramidInfo] = []
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
        self._stats = PyramidStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PyramidStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PyramidInfo]:
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
        """Scaffold a hardened Pyramid main.py entry template."""
        return """\
# Generated by DevAI PyramidAnalyzer
import os

from pyramid.config import Configurator
from pyramid.response import Response


def health(request):
    return Response(json_body={"status": "ok"})


def main(global_config, **settings):
    config = Configurator(settings=settings)
    config.add_route("health", "/health")
    config.add_view(health, route_name="health", renderer="json")
  # config.scan()  # scan your views package here
    return config.make_wsgi_app()


if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    app = main({}, **{
        "session.secret": os.environ.get("SESSION_SECRET", "change-me-in-production"),
    })
    server = make_server("127.0.0.1", 6543, app)
    server.serve_forever()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pyramid: no application files found"
        return (
            f"Pyramid: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pyramid application analysis:",
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
