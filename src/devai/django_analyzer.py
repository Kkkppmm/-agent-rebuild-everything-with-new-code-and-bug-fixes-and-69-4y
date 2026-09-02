"""DjangoAnalyzer — audit Django apps and settings for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DJANGO_ENTRY_NAMES = (
    "settings.py",
    "manage.py",
    "urls.py",
    "wsgi.py",
    "asgi.py",
    "config/settings.py",
    "project/settings.py",
    "app/settings.py",
    "src/settings.py",
    "src/config/settings.py",
)
DJANGO_IMPORT_PATTERN = re.compile(
    r"(?:from\s+django|import\s+django|django\.(?:conf|urls|http|db))",
    re.IGNORECASE,
)
DJANGO_SETTINGS_PATTERN = re.compile(
    r"(?:SECRET_KEY|DEBUG|ALLOWED_HOSTS|DATABASES|INSTALLED_APPS|MIDDLEWARE)\s*=",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|SECRET_KEY)\s*=\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get|env\(|config\())"
    r"(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
DJANGO_INSECURE_SECRET_PATTERN = re.compile(
    r"SECRET_KEY\s*=\s*['\"]django-insecure-[^'\"]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
ALLOWED_HOSTS_WILDCARD_PATTERN = re.compile(
    r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True|"
    r"CORS_ALLOWED_ORIGINS\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"CORS_ALLOW_CREDENTIALS\s*=\s*True[\s\S]{0,120}(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True|"
    r"(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True[\s\S]{0,120}CORS_ALLOW_CREDENTIALS\s*=\s*True",
    re.IGNORECASE,
)
COOKIE_INSECURE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False",
    re.IGNORECASE,
)
COOKIE_HTTPONLY_FALSE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_HTTPONLY)\s*=\s*False",
    re.IGNORECASE,
)
SAME_SITE_NONE_PATTERN = re.compile(
    r"(?:SESSION_COOKIE_SAMESITE|CSRF_COOKIE_SAMESITE)\s*=\s*['\"]None['\"]",
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
DEBUG_MODE_PATTERN = re.compile(
    r"DEBUG\s*=\s*True",
    re.IGNORECASE,
)
CSRF_EXEMPT_PATTERN = re.compile(
    r"@csrf_exempt|csrf_exempt\s*\(",
    re.IGNORECASE,
)
MARK_SAFE_PATTERN = re.compile(
    r"mark_safe\s*\(",
    re.IGNORECASE,
)
DANGEROUS_ROUTE_PATTERN = re.compile(
    r"path\s*\(\s*['\"](?:/)?(?:admin|debug|internal)",
    re.IGNORECASE,
)
SQL_RAW_PATTERN = re.compile(
    r"(?:\.raw\s*\(|RawSQL\s*\(|\.extra\s*\(\s*[^)]*where\s*=)",
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
SECURE_SSL_REDIRECT_FALSE_PATTERN = re.compile(
    r"SECURE_SSL_REDIRECT\s*=\s*False",
    re.IGNORECASE,
)
X_FRAME_OPTIONS_DISABLED_PATTERN = re.compile(
    r"X_FRAME_OPTIONS\s*=\s*(?:None|['\"]ALLOWALL['\"]|['\"]ALLOW-FROM['\"])",
    re.IGNORECASE,
)
DATABASE_PASSWORD_HARDCODED_PATTERN = re.compile(
    r"['\"]PASSWORD['\"]\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
RUNSERVER_EXPOSED_PATTERN = re.compile(
    r"runserver\s+0\.0\.0\.0|runserver\s+.*--insecure",
    re.IGNORECASE,
)
ADMIN_SITE_PATTERN = re.compile(
    r"admin\.site\.(register|urls)|path\s*\(\s*['\"]admin/?['\"]",
    re.IGNORECASE,
)


@dataclass
class DjangoFinding:
    """A security or best-practice issue in a Django application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DjangoInfo:
    """Parsed metadata about a Django application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_cors: bool = False
    has_auth: bool = False
    has_security_middleware: bool = False
    has_csrf_middleware: bool = False
    has_admin: bool = False
    routes: list[str] = field(default_factory=list)


@dataclass
class DjangoStats:
    """Aggregate Django analysis statistics."""

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


def _contains_django(text: str) -> bool:
    return bool(
        DJANGO_IMPORT_PATTERN.search(text)
        or DJANGO_SETTINGS_PATTERN.search(text)
        or "django." in text
        or "DJANGO_SETTINGS_MODULE" in text
    )


def _looks_like_django_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "django" in text:
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
            if any("django" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    if (root / "manage.py").is_file():
        try:
            if _contains_django((root / "manage.py").read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            pass

    for name in DJANGO_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_django(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class DjangoAnalyzer:
    """Audit Django applications for security and production risks.

    Scans settings, views, and URL configs for hardcoded secrets, DEBUG mode,
    wildcard ALLOWED_HOSTS, disabled CSRF protection, mark_safe XSS risks,
    raw SQL queries, SSRF targets, and insecure cookie settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DjangoFinding] | None = None
        self._stats: DjangoStats | None = None
        self._infos: list[DjangoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Django application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in DJANGO_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_django(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_django_project(self.root):
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
                if path.name in {"migrations", "tests.py", "test_models.py"}:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_django(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DjangoFinding],
        info: DjangoInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        route_match = re.search(
            r"path\s*\(\s*['\"]([^'\"]+)['\"]",
            stripped,
            re.IGNORECASE,
        )
        if route_match:
            route = route_match.group(1)
            if route not in info.routes:
                info.routes.append(route)

        if any(k in stripped for k in ("corsheaders", "CORS_", "django-cors-headers")):
            info.has_cors = True
        if any(
            k in stripped
            for k in (
                "login_required",
                "permission_required",
                "IsAuthenticated",
                "AuthenticationMiddleware",
            )
        ):
            info.has_auth = True
        if "SecurityMiddleware" in stripped:
            info.has_security_middleware = True
        if "CsrfViewMiddleware" in stripped:
            info.has_csrf_middleware = True
        if ADMIN_SITE_PATTERN.search(stripped):
            info.has_admin = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Django app — use environment variables or django-environ"),
            (DJANGO_INSECURE_SECRET_PATTERN, "django_insecure_secret", "high",
             "django-insecure SECRET_KEY — generate a unique secret for production"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Django app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Django app — use HTTPS"),
            (ALLOWED_HOSTS_WILDCARD_PATTERN, "allowed_hosts_wildcard", "high",
             "ALLOWED_HOSTS includes '*' — restrict to trusted hostnames"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allows all origins — restrict to trusted origins"),
            (CORS_CREDENTIALS_WILDCARD_PATTERN, "cors_credentials_wildcard", "high",
             "CORS allows credentials with all origins — credential leak risk"),
            (COOKIE_INSECURE_PATTERN, "cookie_insecure", "medium",
             "session/CSRF cookie secure=False — enable in production"),
            (COOKIE_HTTPONLY_FALSE_PATTERN, "cookie_httponly_false", "medium",
             "session/CSRF cookie httponly=False — enable HTTPONLY"),
            (SAME_SITE_NONE_PATTERN, "cookie_samesite_none", "medium",
             "cookie samesite='None' — ensure SECURE cookies are enabled"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Django app — avoid dynamic code execution"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "DEBUG=True — disable in production"),
            (CSRF_EXEMPT_PATTERN, "csrf_exempt", "high",
             "@csrf_exempt — review CSRF protection on this view"),
            (MARK_SAFE_PATTERN, "mark_safe_xss", "high",
             "mark_safe() — XSS risk; ensure input is sanitized"),
            (DANGEROUS_ROUTE_PATTERN, "dangerous_route", "high",
             "admin/debug/internal route — ensure authentication is required"),
            (SQL_RAW_PATTERN, "sql_raw", "high",
             "raw SQL query — use ORM or parameterized queries"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (SECURE_SSL_REDIRECT_FALSE_PATTERN, "ssl_redirect_disabled", "medium",
             "SECURE_SSL_REDIRECT=False — enable HTTPS redirect in production"),
            (X_FRAME_OPTIONS_DISABLED_PATTERN, "x_frame_options_disabled", "medium",
             "X_FRAME_OPTIONS disabled — enable clickjacking protection"),
            (DATABASE_PASSWORD_HARDCODED_PATTERN, "database_password_hardcoded", "high",
             "hardcoded database password — load from environment variables"),
            (RUNSERVER_EXPOSED_PATTERN, "runserver_exposed", "medium",
             "runserver bound to 0.0.0.0 or --insecure — use a production WSGI server"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    DjangoFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[DjangoFinding], DjangoInfo]:
        findings: list[DjangoFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DjangoInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = DjangoInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if CORS_CREDENTIALS_WILDCARD_PATTERN.search(raw_text):
            if not any(f.kind == "cors_credentials_wildcard" for f in findings):
                findings.append(
                    DjangoFinding(
                        kind="cors_credentials_wildcard",
                        severity="high",
                        message="CORS allows credentials with all origins — credential leak risk",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[DjangoFinding]:
        """Scan Django application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DjangoFinding] = []
        infos: list[DjangoInfo] = []
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
        self._stats = DjangoStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DjangoStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DjangoInfo]:
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
        """Scaffold a hardened Django settings.py entry template."""
        return """\
# Generated by DevAI DjangoAnalyzer
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = False
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "example.com").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Django: no application files found"
        return (
            f"Django: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Django application analysis:",
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
