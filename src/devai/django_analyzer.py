"""DjangoAnalyzer — audit Django settings and apps for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DJANGO_SETTINGS_NAMES = (
    "settings.py",
    "local_settings.py",
    "production.py",
    "prod.py",
    "development.py",
    "dev.py",
    "base.py",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:SECRET_KEY|PASSWORD|API[_-]?KEY|TOKEN|CREDENTIAL)\s*=\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
DEBUG_TRUE_PATTERN = re.compile(r"\bDEBUG\s*=\s*True\b")
ALLOWED_HOSTS_WILDCARD_PATTERN = re.compile(
    r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
CSRF_DISABLED_PATTERN = re.compile(
    r"CSRF_(?:COOKIE_SECURE|USE_SESSIONS)\s*=\s*False",
    re.IGNORECASE,
)
SESSION_INSECURE_PATTERN = re.compile(
    r"SESSION_COOKIE_SECURE\s*=\s*False",
    re.IGNORECASE,
)
SSL_REDIRECT_DISABLED_PATTERN = re.compile(
    r"SECURE_SSL_REDIRECT\s*=\s*False",
    re.IGNORECASE,
)
CORS_ALLOW_ALL_PATTERN = re.compile(
    r"CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True",
    re.IGNORECASE,
)
MARK_SAFE_PATTERN = re.compile(r"\bmark_safe\s*\(", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
    re.IGNORECASE,
)
INTERNAL_SSRF_PATTERN = re.compile(
    r"['\"]https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)[^'\"]+['\"]",
    re.IGNORECASE,
)
X_FRAME_ALLOW_PATTERN = re.compile(
    r"X_FRAME_OPTIONS\s*=\s*['\"]ALLOW(?:ALL|FROM)?['\"]",
    re.IGNORECASE,
)
HSTS_DISABLED_PATTERN = re.compile(
    r"SECURE_HSTS_SECONDS\s*=\s*0",
    re.IGNORECASE,
)


@dataclass
class DjangoFinding:
    """A security or best-practice issue in Django configuration."""

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
    """Parsed metadata about a Django settings file."""

    path: str
    lines: int = 0
    has_database: bool = False
    has_middleware: bool = False
    has_installed_apps: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class DjangoStats:
    """Aggregate Django analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_django_settings(path: Path) -> bool:
    if path.name in DJANGO_SETTINGS_NAMES:
        return True
    if path.parent.name == "settings" and path.suffix == ".py" and path.name != "__init__.py":
        return True
    return False


def _looks_like_django_project(root: Path) -> bool:
    if (root / "manage.py").is_file():
        return True
    for pattern in ("**/settings.py", "settings/*.py"):
        if any(root.glob(pattern)):
            return True
    for req in ("requirements.txt", "pyproject.toml"):
        path = root / req
        if path.is_file() and "django" in path.read_text(encoding="utf-8", errors="replace").lower():
            return True
    return False


class DjangoAnalyzer:
    """Audit Django settings for DEBUG exposure, wildcard hosts, CSRF issues, and SSRF risks.

    Scans settings.py and settings/*.py for hardcoded secrets, insecure cookies,
    disabled HTTPS redirects, open CORS, mark_safe usage, and internal URL targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DjangoFinding] | None = None
        self._stats: DjangoStats | None = None
        self._infos: list[DjangoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Django settings paths found in the project."""
        found: list[Path] = []
        for name in DJANGO_SETTINGS_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        settings_dir = self.root / "settings"
        if settings_dir.is_dir():
            for path in sorted(settings_dir.glob("*.py")):
                if path.name != "__init__.py" and path not in found:
                    found.append(path)
        for pattern in ("**/settings.py", "settings/*.py"):
            for path in sorted(self.root.rglob(pattern)):
                if (
                    path.is_file()
                    and path not in found
                    and _is_django_settings(path)
                    and "site-packages" not in path.parts
                ):
                    found.append(path)
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

        for section in ("DATABASES", "MIDDLEWARE", "INSTALLED_APPS"):
            if section in stripped:
                if section not in info.sections:
                    info.sections.append(section)
                if section == "DATABASES":
                    info.has_database = True
                elif section == "MIDDLEWARE":
                    info.has_middleware = True
                elif section == "INSTALLED_APPS":
                    info.has_installed_apps = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Django settings — use environment variables"),
            (DEBUG_TRUE_PATTERN, "debug_enabled", "high",
             "DEBUG=True exposes stack traces and sensitive data — disable in production"),
            (ALLOWED_HOSTS_WILDCARD_PATTERN, "allowed_hosts_wildcard", "high",
             "ALLOWED_HOSTS=['*'] accepts any Host header — enumerate trusted domains"),
            (INTERNAL_SSRF_PATTERN, "internal_url", "high",
             "URL targets internal IP — SSRF risk in webhooks or callbacks"),
            (MARK_SAFE_PATTERN, "mark_safe", "high",
             "mark_safe() bypasses auto-escaping — XSS risk with untrusted input"),
            (CORS_ALLOW_ALL_PATTERN, "cors_allow_all", "medium",
             "CORS allows all origins — restrict to trusted frontends"),
            (CSRF_DISABLED_PATTERN, "csrf_insecure", "medium",
             "CSRF cookie security disabled — enable secure CSRF cookies"),
            (SESSION_INSECURE_PATTERN, "session_insecure", "medium",
             "SESSION_COOKIE_SECURE=False — session cookies sent over HTTP"),
            (SSL_REDIRECT_DISABLED_PATTERN, "ssl_redirect_disabled", "medium",
             "SECURE_SSL_REDIRECT=False — HTTP requests not redirected to HTTPS"),
            (HSTS_DISABLED_PATTERN, "hsts_disabled", "medium",
             "SECURE_HSTS_SECONDS=0 — HSTS not enforced"),
            (X_FRAME_ALLOW_PATTERN, "clickjacking_risk", "medium",
             "X_FRAME_OPTIONS allows framing — clickjacking risk"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "low",
             "HTTP URL in settings — prefer HTTPS for external services"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    DjangoFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
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
        info = DjangoInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[DjangoFinding]:
        """Scan Django settings files and return findings."""
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
        """Scaffold a hardened Django settings snippet."""
        return """\
# Generated by DevAI DjangoAnalyzer
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")

SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
X_FRAME_OPTIONS = "DENY"

CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Django: no settings files found"
        return (
            f"Django: {stats.configs} settings file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Django settings analysis:",
            f"  settings files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: sections={','.join(info.sections) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
