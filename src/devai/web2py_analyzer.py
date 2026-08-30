"""Web2pyAnalyzer — audit web2py apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

WEB2PY_ENTRY_NAMES = (
    "wsgi.py",
    "app.py",
    "routes.py",
    "models/db.py",
    "models/0.py",
    "controllers/default.py",
    "applications/welcome/controllers/default.py",
    "applications/welcome/models/db.py",
    "private/appconfig.py",
)
WEB2PY_IMPORT_PATTERN = re.compile(
    r"(?:from\s+gluon(?:\.\w+)?\s+import|import\s+gluon|"
    r"\bDAL\s*\(|\bSQLFORM\s*\(|\bAuth\s*\(|\bService\s*\(|\bCrud\s*\(|"
    r"current\.request|current\.response|current\.session|"
    r"@auth\.requires|@request\.restful)",
    re.IGNORECASE,
)
WEB2PY_ROUTE_PATTERN = re.compile(
    r"@(?:auth\.requires|request\.restful|service\.jsonrpc|service\.xmlrpc)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|hmac[_-]?key|encryption_key)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get|request\.env))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
DB_CREDENTIAL_PATTERN = re.compile(
    r"DAL\s*\(\s*['\"](?:mysql|postgres|postgresql|mssql|oracle)://[^:]+:[^@]+@",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|"
    r"response\.headers\s*\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"Access-Control-Allow-Credentials['\"]?\s*[:=]\s*True[\s\S]{0,120}Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|"
    r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"][\s\S]{0,120}Access-Control-Allow-Credentials['\"]?\s*[:=]\s*True",
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
    r"(?:global_settings\.debug|request\.is_local)\s*=\s*True|debug\s*=\s*True",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"def\s+(?:admin|debug|internal|shell|eval)\s*\(",
    re.IGNORECASE,
)
SQL_RAW_PATTERN = re.compile(
    r"(?:executesql|db\.executesql)\s*\(\s*f?['\"].*(?:SELECT|INSERT|UPDATE|DELETE)",
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
    r"(?:csrfguard_disabled|csrf_protection)\s*=\s*False|"
    r"request\.csrfguard_disabled\s*=\s*True",
    re.IGNORECASE,
)
INSECURE_SESSION_PATTERN = re.compile(
    r"(?:session\.secure|session\.httponly)\s*=\s*False",
    re.IGNORECASE,
)
AUTH_WEAK_PATTERN = re.compile(
    r"auth\.settings\.(?:disable_password_verification|registration_requires_verification)\s*=\s*False|"
    r"auth\.settings\.password_min_length\s*=\s*[0-3]\b",
    re.IGNORECASE,
)
SSTI_PATTERN = re.compile(
    r"(?:BEAUTIFY|XML)\s*\([^)]*(?:request\.vars|request\.get_vars|request\.post_vars)",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"redirect\s*\(\s*(?:request\.vars|request\.get_vars|request\.post_vars)",
    re.IGNORECASE,
)
MASS_ASSIGNMENT_PATTERN = re.compile(
    r"(?:insert|update_record)\s*\(\s*\*\*(?:request\.vars|request\.get_vars|request\.post_vars)",
    re.IGNORECASE,
)
AJAX_SERVER_PATTERN = re.compile(
    r"ajax_server_enabled\s*=\s*True",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:host|bind)\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)


@dataclass
class Web2pyFinding:
    """A security or best-practice issue in a web2py application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class Web2pyInfo:
    """Parsed metadata about a web2py application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_debug: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class Web2pyStats:
    """Aggregate web2py analysis statistics."""

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


def _contains_web2py(text: str) -> bool:
    return bool(
        WEB2PY_IMPORT_PATTERN.search(text)
        or WEB2PY_ROUTE_PATTERN.search(text)
        or "gluon." in text
        or "web2py" in text.lower()
    )


def _looks_like_web2py_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "web2py" in text or "gluon" in text:
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
            if any("web2py" in str(dep).lower() or "gluon" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    if (root / "applications").is_dir():
        return True

    for name in WEB2PY_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_web2py(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class Web2pyAnalyzer:
    """Audit web2py applications for security and production risks.

    Scans web2py controllers, models, and config for hardcoded secrets,
    debug mode, disabled CSRF, weak auth settings, DAL credential leaks,
    SSRF targets, shell command execution, mass assignment, and open redirects.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[Web2pyFinding] | None = None
        self._stats: Web2pyStats | None = None
        self._infos: list[Web2pyInfo] | None = None

    def configs(self) -> list[Path]:
        """Return web2py application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in WEB2PY_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_web2py(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_web2py_project(self.root):
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
                if _contains_web2py(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[Web2pyFinding],
        info: Web2pyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
            stripped,
            re.IGNORECASE,
        )
        if route_match and route_match.group(1) not in info.routes:
            info.routes.append(route_match.group(1))

        if "Access-Control-Allow-Origin" in stripped:
            info.has_cors = True
        if "global_settings.debug" in stripped or "debug = True" in stripped:
            info.has_debug = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in web2py app — use environment variables or appconfig"),
            (DB_CREDENTIAL_PATTERN, "db_credentials", "high",
             "database credentials in DAL connection string — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in web2py app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in web2py app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS Access-Control-Allow-Origin includes '*' — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with wildcard origins — credential leak risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in web2py app — avoid dynamic code execution"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal endpoint — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL via executesql — use parameterized queries to prevent SQL injection"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (CSRF_DISABLED_PATTERN, "csrf_disabled", "high",
             "CSRF protection disabled — enable CSRF for state-changing requests"),
            (INSECURE_SESSION_PATTERN, "insecure_session", "high",
             "session cookie missing secure/httponly flags"),
            (AUTH_WEAK_PATTERN, "weak_auth", "high",
             "weak auth settings — enforce password verification and minimum length"),
            (SSTI_PATTERN, "xss_unescaped", "high",
             "BEAUTIFY/XML with user input — validate or escape to prevent XSS"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "high",
             "redirect with user-controlled URL — validate redirect targets"),
            (MASS_ASSIGNMENT_PATTERN, "mass_assignment", "high",
             "mass assignment from request vars — whitelist allowed fields"),
            (AJAX_SERVER_PATTERN, "ajax_server_enabled", "medium",
             "ajax_server_enabled — restrict to trusted origins in production"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "web2py bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    Web2pyFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[Web2pyFinding], Web2pyInfo]:
        findings: list[Web2pyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, Web2pyInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = Web2pyInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    Web2pyFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with wildcard origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[Web2pyFinding]:
        """Scan web2py application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Web2pyFinding] = []
        infos: list[Web2pyInfo] = []
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
        self._stats = Web2pyStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> Web2pyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[Web2pyInfo]:
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
        """Scaffold a hardened web2py models/db.py entry template."""
        return """\
# Generated by DevAI Web2pyAnalyzer
import os

from gluon import current
from gluon.contrib.appconfig import AppConfig
from gluon.tools import Auth

myconf = AppConfig(reload=True)

db = DAL(
    os.environ.get("DATABASE_URL", "sqlite://storage.sqlite"),
    migrate=True,
    pool_size=10,
)
db.commit()

auth = Auth(db, hmac_key=os.environ.get("AUTH_HMAC_KEY", "change-me-in-production"))
auth.define_tables(username=False, signature=False)

auth.settings.registration_requires_verification = True
auth.settings.password_min_length = 12
auth.settings.reset_password_requires_verification = True

current.session.secure = True
current.session.httponly = True
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "web2py: no application files found"
        return (
            f"web2py: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "web2py application analysis:",
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
