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
    "application.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "app/main.py",
    "app/__init__.py",
)
CHERRYPY_IMPORT_PATTERN = re.compile(
    r"(?:from\s+cherrypy|import\s+cherrypy|cherrypy\.(?:tree|config|quickstart|engine|expose))",
    re.IGNORECASE,
)
CHERRYPY_EXPOSE_PATTERN = re.compile(
    r"@cherrypy\.expose|cherrypy\.expose\s*\(",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|cookie_secret|tools\.sessions\.secret)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|"
    r"\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*['\"]\*['\"]|"
    r"allow_origin\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Credentials['\"]?\s*[:=]\s*True[\s\S]{0,120}Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|"
    r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"][\s\S]{0,120}Access-Control-Allow-Credentials['\"]?\s*[:=]\s*True|"
    r"\[\s*['\"]Access-Control-Allow-Credentials['\"]\s*\]\s*=\s*True[\s\S]{0,120}"
    r"\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*['\"]\*['\"]|"
    r"\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*['\"]\*['\"][\s\S]{0,120}"
    r"\[\s*['\"]Access-Control-Allow-Credentials['\"]\s*\]\s*=\s*True",
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
    r"(?:server\.environment|environment)\s*[=:]\s*['\"]development['\"]|"
    r"engine\.autoreload\.on\s*=\s*True|"
    r"['\"]server\.environment['\"]\s*:\s*['\"]development['\"]",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"@cherrypy\.expose(?:\([^)]*\))?\s*\n\s*def\s+(?:admin|debug|internal)",
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
STATIC_USER_INPUT_PATTERN = re.compile(
    r"(?:serve_file|tools\.staticdir\.dir)\s*[=:][^,\n]*(?:cherrypy\.request|getattr|\.params|\.args)",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"server\.socket_host\s*[=:]\s*['\"]0\.0\.0\.0['\"]|"
    r"['\"]server\.socket_host['\"]\s*:\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
SESSIONS_DISABLED_PATTERN = re.compile(
    r"tools\.sessions\.on\s*=\s*False|['\"]tools\.sessions\.on['\"]\s*:\s*False",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"raise\s+cherrypy\.HTTPRedirect\s*\(\s*cherrypy\.request\.(?:params|args)",
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
    has_sessions: bool = False
    exposed_endpoints: list[str] = field(default_factory=list)


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
        or "cherrypy.tree.mount" in text
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

    Scans CherryPy entry files, exposed endpoints, and config for hardcoded secrets,
    development mode, open CORS, SSRF targets, shell command execution, and
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
            r"@cherrypy\.expose(?:\([^)]*\))?\s*$|def\s+(\w+)\s*\(",
            stripped,
            re.IGNORECASE,
        )
        if "@cherrypy.expose" in stripped.lower():
            next_def = re.search(r"def\s+(\w+)\s*\(", stripped)
            if next_def and next_def.group(1) not in info.exposed_endpoints:
                info.exposed_endpoints.append(next_def.group(1))

        if "Access-Control-Allow-Origin" in stripped or "allow_origin" in stripped:
            info.has_cors = True
        if "tools.sessions" in stripped and "True" in stripped:
            info.has_sessions = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in CherryPy app — use environment variables or config files"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in CherryPy app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in CherryPy app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS Access-Control-Allow-Origin includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in CherryPy app — avoid dynamic code execution"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "development mode or autoreload enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal endpoint — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (STATIC_USER_INPUT_PATTERN, "static_file_user_input", "high",
             "static file/dir from user input — validate paths to prevent traversal"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "CherryPy bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (SESSIONS_DISABLED_PATTERN, "sessions_disabled", "medium",
             "session tool disabled — enable sessions for authenticated apps"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "high",
             "redirect with user-controlled URL — validate redirect targets"),
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
        """Scaffold a hardened CherryPy main.py entry template."""
        return """\
# Generated by DevAI CherryPyAnalyzer
import os

import cherrypy


class Health:
    @cherrypy.expose
    def index(self):
        return {"status": "ok"}


def main() -> None:
    cherrypy.config.update(
        {
            "server.socket_host": os.environ.get("HOST", "127.0.0.1"),
            "server.socket_port": int(os.environ.get("PORT", "8080")),
            "server.environment": "production",
            "tools.sessions.on": True,
            "tools.sessions.secret": os.environ.get("SESSION_SECRET", "change-me-in-production"),
            "engine.autoreload.on": False,
        }
    )
    cherrypy.quickstart(Health(), "/health")


if __name__ == "__main__":
    main()
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
                f"endpoints={','.join(info.exposed_endpoints[:5]) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
