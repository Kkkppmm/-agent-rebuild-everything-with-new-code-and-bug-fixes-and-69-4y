"""TornadoAnalyzer — audit Tornado apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

TORNADO_ENTRY_NAMES = (
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
TORNADO_IMPORT_PATTERN = re.compile(
    r"(?:from\s+tornado|import\s+tornado|tornado\.(?:web|ioloop|httpserver|options))",
    re.IGNORECASE,
)
TORNADO_APP_PATTERN = re.compile(
    r"tornado\.web\.Application\s*\(|web\.Application\s*\(",
    re.IGNORECASE,
)
TORNADO_HANDLER_PATTERN = re.compile(
    r"class\s+\w+\s*\(\s*(?:tornado\.)?web\.(?:RequestHandler|StaticFileHandler)\s*\)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|cookie_secret|COOKIE_SECRET)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get|options\.))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:CORS|tornado_cors)[^)]*(?:allow_origin|allow_origins)\s*=\s*['\"]\*['\"]|"
    r"(?:allow_origin|allow_origins)\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"allow_credentials\s*=\s*True[\s\S]{0,120}(?:allow_origin|allow_origins)\s*=\s*['\"]\*['\"]|"
    r"(?:allow_origin|allow_origins)\s*=\s*['\"]\*['\"][\s\S]{0,120}allow_credentials\s*=\s*True",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"validate_certificate\s*=\s*False|ssl_options\s*=\s*\{[^}]*cert_reqs[^}]*CERT_NONE",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:AsyncHTTPClient|httpclient)\.(?:fetch|AsyncHTTPClient)\s*\([^)]*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:debug|autoreload)\s*=\s*True|"
    r"\"debug\"\s*:\s*True|"
    r"'debug'\s*:\s*True",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"xsrf_cookies\s*=\s*False|\"xsrf_cookies\"\s*:\s*False|'xsrf_cookies'\s*:\s*False",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"\(\s*r?['\"](?:/)?(?:admin|debug|internal)",
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
STATIC_FILE_USER_INPUT_PATTERN = re.compile(
    r"StaticFileHandler\s*\([^)]*(?:self\.get_argument|get_query_argument|request\.arguments)",
    re.IGNORECASE,
)
AUTOESCAPE_DISABLED_PATTERN = re.compile(
    r"autoescape\s*=\s*(?:None|False)|\"autoescape\"\s*:\s*(?:None|False)",
    re.IGNORECASE,
)
INSECURE_COOKIE_PATTERN = re.compile(
    r"(?:secure|httponly)\s*=\s*False",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"self\.redirect\s*\(\s*self\.get_(?:argument|query_argument)\s*\(",
    re.IGNORECASE,
)


@dataclass
class TornadoFinding:
    """A security or best-practice issue in a Tornado application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TornadoInfo:
    """Parsed metadata about a Tornado application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_xsrf: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class TornadoStats:
    """Aggregate Tornado analysis statistics."""

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


def _contains_tornado(text: str) -> bool:
    return bool(
        TORNADO_IMPORT_PATTERN.search(text)
        or TORNADO_APP_PATTERN.search(text)
        or TORNADO_HANDLER_PATTERN.search(text)
    )


def _looks_like_tornado_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "tornado" in text:
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
            if any("tornado" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in TORNADO_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_tornado(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class TornadoAnalyzer:
    """Audit Tornado applications for security and production risks.

    Scans Tornado entry files, handlers, and settings for hardcoded secrets,
    disabled XSRF protection, debug mode, SSRF targets, shell command execution,
    and unprotected admin routes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TornadoFinding] | None = None
        self._stats: TornadoStats | None = None
        self._infos: list[TornadoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Tornado application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in TORNADO_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_tornado(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_tornado_project(self.root):
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
                if _contains_tornado(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TornadoFinding],
        info: TornadoInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"\(\s*r?['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if route_match and ("Handler" in stripped or "Application" in stripped):
            route = route_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        if "CORS(" in stripped or "tornado_cors" in stripped.lower():
            info.has_cors = True
        if any(k in stripped for k in ("@web.authenticated", "@tornado.web.authenticated", "get_current_user")):
            info.has_auth = True
        if "xsrf_cookies" in stripped and "True" in stripped:
            info.has_xsrf = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Tornado app — use environment variables or options"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Tornado app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Tornado app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origin includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (INSECURE_COOKIE_PATTERN, "cookie_insecure", "medium",
             "cookie secure/httponly=False — enable secure cookies in production"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Tornado app — avoid dynamic code execution"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug/autoreload enabled — disable in production"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF cookies disabled — enable xsrf_cookies to prevent CSRF attacks"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (STATIC_FILE_USER_INPUT_PATTERN, "static_file_user_input", "high",
             "StaticFileHandler with user input — validate paths to prevent traversal"),
            (AUTOESCAPE_DISABLED_PATTERN, "autoescape_disabled", "high",
             "template autoescape disabled — enable autoescape to prevent XSS"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "high",
             "redirect with user-controlled URL — validate redirect targets"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    TornadoFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[TornadoFinding], TornadoInfo]:
        findings: list[TornadoFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, TornadoInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = TornadoInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    TornadoFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[TornadoFinding]:
        """Scan Tornado application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TornadoFinding] = []
        infos: list[TornadoInfo] = []
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
        self._stats = TornadoStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TornadoStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TornadoInfo]:
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
        """Scaffold a hardened Tornado main.py entry template."""
        return """\
# Generated by DevAI TornadoAnalyzer
import os

import tornado.ioloop
import tornado.web


class HealthHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"status": "ok"})


def make_app() -> tornado.web.Application:
    return tornado.web.Application(
        [
            (r"/health", HealthHandler),
        ],
        cookie_secret=os.environ.get("COOKIE_SECRET", "change-me-in-production"),
        xsrf_cookies=True,
        debug=False,
        autoreload=False,
    )


def main() -> None:
    app = make_app()
    app.listen(int(os.environ.get("PORT", "8888")))
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Tornado: no application files found"
        return (
            f"Tornado: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Tornado application analysis:",
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
