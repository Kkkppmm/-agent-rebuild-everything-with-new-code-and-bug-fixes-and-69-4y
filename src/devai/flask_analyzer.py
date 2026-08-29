"""FlaskAnalyzer — audit Flask apps for debug mode, secrets, CORS, SSTI, and SSRF risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FLASK_ENTRY_NAMES = (
    "app.py",
    "wsgi.py",
    "application.py",
    "server.py",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:SECRET_KEY|API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL).*?=\s*"
    r"['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
DEBUG_TRUE_PATTERN = re.compile(
    r"(?:app\.run\s*\([^)]*debug\s*=\s*True|(?:DEBUG|FLASK_DEBUG).*?=\s*True)",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:origins|CORS_ORIGINS)\s*[=:]\s*(?:\[)?\s*['\"]\*['\"]",
    re.IGNORECASE,
)
SSTI_PATTERN = re.compile(r"\brender_template_string\s*\(", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
    re.IGNORECASE,
)
INTERNAL_SSRF_PATTERN = re.compile(
    r"['\"]https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)[^'\"]+['\"]",
    re.IGNORECASE,
)
SESSION_INSECURE_PATTERN = re.compile(
    r"SESSION_COOKIE_SECURE.*?=\s*False",
    re.IGNORECASE,
)
COOKIE_HTTPONLY_DISABLED_PATTERN = re.compile(
    r"SESSION_COOKIE_HTTPONLY.*?=\s*False",
    re.IGNORECASE,
)
PERMANENT_SESSION_LIFETIME_LONG_PATTERN = re.compile(
    r"PERMANENT_SESSION_LIFETIME.*?timedelta\s*\(\s*days\s*=\s*\d{3,}",
    re.IGNORECASE,
)
FLASK_IMPORT_PATTERN = re.compile(r"\bfrom\s+flask\b|\bimport\s+flask\b|Flask\s*\(")


@dataclass
class FlaskFinding:
    """A security or best-practice issue in a Flask application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class FlaskInfo:
    """Parsed metadata about a Flask application file."""

    path: str
    lines: int = 0
    has_cors: bool = False
    has_blueprint: bool = False
    has_session: bool = False
    sections: list[str] = field(default_factory=list)


@dataclass
class FlaskStats:
    """Aggregate Flask analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_flask_file(path: Path, content: str | None = None) -> bool:
    if path.name in FLASK_ENTRY_NAMES:
        return True
    if path.suffix != ".py":
        return False
    if content is None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(FLASK_IMPORT_PATTERN.search(content))


class FlaskAnalyzer:
    """Audit Flask applications for debug mode, hardcoded secrets, CORS, SSTI, and SSRF risks.

    Scans app.py, wsgi.py, and Flask entrypoints for DEBUG=True, exposed secrets,
    open CORS, render_template_string usage, insecure session cookies, and
    internal redirect/proxy targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FlaskFinding] | None = None
        self._stats: FlaskStats | None = None
        self._infos: list[FlaskInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Flask application paths found in the project."""
        found: list[Path] = []
        for name in FLASK_ENTRY_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*.py")):
            if path in found or "site-packages" in path.parts or ".venv" in path.parts:
                continue
            if _is_flask_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[FlaskFinding],
        info: FlaskInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for section in ("CORS", "Blueprint", "session", "permanent_session_lifetime"):
            if section.lower() in stripped.lower():
                if section not in info.sections:
                    info.sections.append(section)
                if section == "CORS":
                    info.has_cors = True
                elif section == "Blueprint":
                    info.has_blueprint = True
                elif section.lower() == "session":
                    info.has_session = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Flask app — use environment variables"),
            (DEBUG_TRUE_PATTERN, "debug_enabled", "high",
             "Flask debug mode enabled — exposes Werkzeug debugger and stack traces"),
            (SSTI_PATTERN, "ssti_risk", "high",
             "render_template_string() — SSTI risk with untrusted template input"),
            (INTERNAL_SSRF_PATTERN, "internal_url", "high",
             "URL targets internal IP — SSRF risk in redirects or webhooks"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "medium",
             "CORS origins set to * — any origin may access the API"),
            (SESSION_INSECURE_PATTERN, "session_insecure", "medium",
             "SESSION_COOKIE_SECURE=False — session cookies sent over HTTP"),
            (COOKIE_HTTPONLY_DISABLED_PATTERN, "httponly_disabled", "medium",
             "SESSION_COOKIE_HTTPONLY=False — session cookie readable by JavaScript"),
            (PERMANENT_SESSION_LIFETIME_LONG_PATTERN, "long_session_lifetime", "low",
             "very long session lifetime — increases session hijacking window"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "low",
             "HTTP URL in Flask app — prefer HTTPS for external services"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    FlaskFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[FlaskFinding], FlaskInfo]:
        findings: list[FlaskFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, FlaskInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = FlaskInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[FlaskFinding]:
        """Scan Flask application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FlaskFinding] = []
        infos: list[FlaskInfo] = []
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
        self._stats = FlaskStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FlaskStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FlaskInfo]:
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
        """Scaffold a hardened Flask application template."""
        return """\
# Generated by DevAI FlaskAnalyzer
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.config["SESSION_COOKIE_SECURE"] = not app.config["DEBUG"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Flask: no application files found"
        return (
            f"Flask: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Flask application analysis:",
            f"  application files: {stats.configs}",
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
