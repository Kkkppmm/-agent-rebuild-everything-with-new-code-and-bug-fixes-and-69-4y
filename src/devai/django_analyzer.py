"""DjangoAnalyzer — audit Django apps and settings for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DJANGO_ENTRY_NAMES = (
    "manage.py",
    "settings.py",
    "config/settings.py",
    "settings/base.py",
    "settings/dev.py",
    "settings/production.py",
    "settings/local.py",
    "project/settings.py",
    "app/settings.py",
    "urls.py",
    "config/urls.py",
    "project/urls.py",
    "wsgi.py",
    "asgi.py",
)
DJANGO_IMPORT_PATTERN = re.compile(
    r"(?:from\s+django|import\s+django|INSTALLED_APPS|django\.conf|django\.contrib)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|SECRET_KEY)\s*=\s*"
    r"(?!\s*(?:os\.environ|env\(|getenv|environ\.get|config\(|decouple|django\.conf))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
SECRET_KEY_HARDCODED_PATTERN = re.compile(
    r"SECRET_KEY\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DEBUG_TRUE_PATTERN = re.compile(
    r"DEBUG\s*=\s*True",
    re.IGNORECASE,
)
ALLOWED_HOSTS_WILDCARD_PATTERN = re.compile(
    r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
CORS_ALLOW_ALL_PATTERN = re.compile(
    r"(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True",
    re.IGNORECASE,
)
CORS_CREDENTIALS_WILDCARD_PATTERN = re.compile(
    r"CORS_ALLOW_CREDENTIALS\s*=\s*True[\s\S]{0,160}CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|"
    r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True[\s\S]{0,160}CORS_ALLOW_CREDENTIALS\s*=\s*True",
    re.IGNORECASE,
)
SESSION_COOKIE_INSECURE_PATTERN = re.compile(
    r"SESSION_COOKIE_SECURE\s*=\s*False",
    re.IGNORECASE,
)
SESSION_COOKIE_HTTPONLY_FALSE_PATTERN = re.compile(
    r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
    re.IGNORECASE,
)
CSRF_COOKIE_INSECURE_PATTERN = re.compile(
    r"CSRF_COOKIE_SECURE\s*=\s*False",
    re.IGNORECASE,
)
SAME_SITE_NONE_PATTERN = re.compile(
    r"SESSION_COOKIE_SAMESITE\s*=\s*['\"]None['\"]",
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
RAW_SQL_PATTERN = re.compile(
    r"(?:\.raw\s*\(|RawSQL\s*\(|\.extra\s*\(|cursor\.execute\s*\(\s*f?['\"])",
    re.IGNORECASE,
)
DEBUG_TOOLBAR_PATTERN = re.compile(
    r"['\"]debug_toolbar['\"]",
    re.IGNORECASE,
)
DATABASE_HARDCODED_PATTERN = re.compile(
    r"['\"]PASSWORD['\"]\s*:\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
STATIC_SERVE_PATTERN = re.compile(
    r"django\.views\.static\.serve|static\s*\(\s*[^)]*document_root",
    re.IGNORECASE,
)
PICKLE_SERIALIZER_PATTERN = re.compile(
    r"PickleSerializer|django\.contrib\.sessions\.serializers\.PickleSerializer",
    re.IGNORECASE,
)
WEAK_HASHER_PATTERN = re.compile(
    r"['\"]django\.contrib\.auth\.hashers\.(?:MD5|SHA1)PasswordHasher['\"]",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False|CERT_NONE",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|urllib|httpx|aiohttp)\.(?:get|post|request|urlopen)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"runserver\s+0\.0\.0\.0|host\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
DANGEROUS_URL_PATTERN = re.compile(
    r"path\s*\(\s*['\"](?:admin/debug|debug/|internal/|admin/users)",
    re.IGNORECASE,
)
INSECURE_X_FRAME_PATTERN = re.compile(
    r"X_FRAME_OPTIONS\s*=\s*['\"]ALLOW['\"]|"
    r"XFrameOptionsMiddleware",
    re.IGNORECASE,
)
ADMIN_DEFAULT_PATTERN = re.compile(
    r"path\s*\(\s*['\"]admin/['\"]",
    re.IGNORECASE,
)


@dataclass
class DjangoFinding:
    """A security or best-practice issue in a Django project file."""

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
    """Parsed metadata about a Django project file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_debug_toolbar: bool = False
    has_cors: bool = False
    has_csrf_exempt: bool = False
    has_admin: bool = False
    has_https_settings: bool = False
    settings_flags: list[str] = field(default_factory=list)


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
        or "django.contrib" in text
        or "DJANGO_SETTINGS_MODULE" in text
    )


def _looks_like_django_project(root: Path) -> bool:
    if (root / "manage.py").is_file():
        return True

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
    """Audit Django projects for security and production risks.

    Scans settings, urls, and views for hardcoded SECRET_KEY, DEBUG=True,
    open ALLOWED_HOSTS/CORS, disabled cookie security, csrf_exempt abuse,
    mark_safe XSS risks, raw SQL, debug toolbar in production, and SSRF targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DjangoFinding] | None = None
        self._stats: DjangoStats | None = None
        self._infos: list[DjangoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Django configuration paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in DJANGO_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_django(text) or name in {"manage.py", "settings.py", "urls.py"}:
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
                if path.name not in {
                    "settings.py",
                    "urls.py",
                    "views.py",
                    "wsgi.py",
                    "asgi.py",
                    "manage.py",
                } and "settings" not in path.parts:
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

        if "debug_toolbar" in stripped.lower():
            info.has_debug_toolbar = True
        if any(k in stripped for k in ("CORS_", "corsheaders", "django-cors-headers")):
            info.has_cors = True
        if CSRF_EXEMPT_PATTERN.search(stripped):
            info.has_csrf_exempt = True
        if ADMIN_DEFAULT_PATTERN.search(stripped):
            info.has_admin = True
        if any(
            k in stripped
            for k in ("SECURE_SSL_REDIRECT", "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE")
        ):
            info.has_https_settings = True

        for flag in ("DEBUG", "ALLOWED_HOSTS", "SECRET_KEY", "DATABASES", "INSTALLED_APPS"):
            if flag in stripped and flag not in info.settings_flags:
                info.settings_flags.append(flag)

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Django project — use environment variables"),
            (SECRET_KEY_HARDCODED_PATTERN, "secret_key_hardcoded", "high",
             "hardcoded SECRET_KEY — use environment variables or django-environ"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Django project — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Django project — use HTTPS"),
            (DEBUG_TRUE_PATTERN, "debug_enabled", "high",
             "DEBUG=True — disable in production to prevent information disclosure"),
            (ALLOWED_HOSTS_WILDCARD_PATTERN, "allowed_hosts_wildcard", "high",
             "ALLOWED_HOSTS includes '*' — restrict to trusted hostnames"),
            (CORS_ALLOW_ALL_PATTERN, "cors_allow_all", "high",
             "CORS allows all origins — restrict to trusted domains"),
            (SESSION_COOKIE_INSECURE_PATTERN, "session_cookie_insecure", "medium",
             "SESSION_COOKIE_SECURE=False — enable secure cookies in production"),
            (SESSION_COOKIE_HTTPONLY_FALSE_PATTERN, "session_cookie_httponly_false", "medium",
             "SESSION_COOKIE_HTTPONLY=False — enable HttpOnly session cookies"),
            (CSRF_COOKIE_INSECURE_PATTERN, "csrf_cookie_insecure", "medium",
             "CSRF_COOKIE_SECURE=False — enable secure CSRF cookies in production"),
            (SAME_SITE_NONE_PATTERN, "session_samesite_none", "medium",
             "SESSION_COOKIE_SAMESITE='None' — ensure secure cookies are enabled"),
            (CSRF_EXEMPT_PATTERN, "csrf_exempt", "high",
             "csrf_exempt on view — verify CSRF protection is not bypassed"),
            (MARK_SAFE_PATTERN, "mark_safe", "high",
             "mark_safe() in Django code — XSS risk if user input is involved"),
            (RAW_SQL_PATTERN, "raw_sql", "high",
             "raw SQL or .extra() query — verify parameterization to prevent SQL injection"),
            (DEBUG_TOOLBAR_PATTERN, "debug_toolbar", "medium",
             "django-debug-toolbar in INSTALLED_APPS — remove from production"),
            (DATABASE_HARDCODED_PATTERN, "database_password_hardcoded", "high",
             "hardcoded database password — use environment variables"),
            (STATIC_SERVE_PATTERN, "static_serve", "medium",
             "django.views.static.serve in urls — use a production web server for static files"),
            (PICKLE_SERIALIZER_PATTERN, "pickle_serializer", "high",
             "PickleSerializer for sessions — use JSONSerializer to avoid deserialization attacks"),
            (WEAK_HASHER_PATTERN, "weak_password_hasher", "high",
             "weak password hasher (MD5/SHA1) — use Argon2 or PBKDF2"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Django project — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "runserver bound to 0.0.0.0 — use gunicorn/uvicorn behind a reverse proxy"),
            (DANGEROUS_URL_PATTERN, "dangerous_url", "high",
             "admin/debug/internal URL pattern — ensure authentication is required"),
            (INSECURE_X_FRAME_PATTERN, "x_frame_options", "low",
             "permissive X-Frame-Options — verify clickjacking protection"),
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
        """Scan Django project files and return findings."""
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
        """Scaffold a hardened Django settings.py template."""
        return """\
# Generated by DevAI DjangoAnalyzer
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"

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
            return "Django: no project files found"
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
            "Django project analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"settings={','.join(info.settings_flags) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
