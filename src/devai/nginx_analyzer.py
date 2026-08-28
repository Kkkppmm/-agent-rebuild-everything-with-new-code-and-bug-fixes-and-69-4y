"""NginxAnalyzer — audit Nginx configs for weak TLS, security headers, and proxy issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NGINX_DIRS = ("nginx", "conf.d", "sites-available", "sites-enabled")
NGINX_NAMES = ("nginx.conf",)
NGINX_SUFFIXES = (".conf",)

WEAK_TLS_PATTERN = re.compile(
    r"ssl_protocols\s+[^;]*(TLSv1\s|TLSv1\.1\s|TLSv1\.1;|TLSv1;)",
    re.IGNORECASE,
)
SERVER_TOKENS_ON_PATTERN = re.compile(r"server_tokens\s+on\b", re.IGNORECASE)
AUTOINDEX_ON_PATTERN = re.compile(r"autoindex\s+on\b", re.IGNORECASE)
WILDCARD_CORS_PATTERN = re.compile(
    r"Access-Control-Allow-Origin\s+['\"]?\*['\"]?",
    re.IGNORECASE,
)
INSECURE_PROXY_PATTERN = re.compile(
    r"proxy_pass\s+http://",
    re.IGNORECASE,
)
SSL_VERIFY_OFF_PATTERN = re.compile(
    r"proxy_ssl_verify\s+off\b",
    re.IGNORECASE,
)
HSTS_MISSING_CONTEXT = re.compile(
    r"listen\s+443|ssl_certificate",
    re.IGNORECASE,
)
HSTS_HEADER_PATTERN = re.compile(
    r"Strict-Transport-Security",
    re.IGNORECASE,
)
X_FRAME_OPTIONS_PATTERN = re.compile(r"X-Frame-Options", re.IGNORECASE)
X_CONTENT_TYPE_PATTERN = re.compile(r"X-Content-Type-Options", re.IGNORECASE)


@dataclass
class NginxFinding:
    """A security issue in an Nginx configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NginxInfo:
    """Parsed metadata about an Nginx config."""

    path: str
    server_blocks: int = 0
    has_ssl: bool = False
    lines: int = 0


@dataclass
class NginxStats:
    """Aggregate Nginx analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nginx_config(path: Path) -> bool:
    lower = path.name.lower()
    if lower in ("nginx.conf",):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(NGINX_DIRS):
        return True
    if lower.endswith(".conf") and "nginx" in lower:
        return True
    if lower.endswith(".conf") and parts & set(NGINX_DIRS):
        return True
    return False


class NginxAnalyzer:
    """Audit Nginx configs for weak TLS, security headers, wildcard CORS, and insecure proxy_pass.

    Scans nginx.conf and site configs for TLS 1.0/1.1, missing HSTS, server_tokens on,
    autoindex, wildcard CORS, and HTTP upstream proxy_pass.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NginxFinding] | None = None
        self._stats: NginxStats | None = None
        self._infos: list[NginxInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Nginx config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_nginx_config(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[NginxFinding], NginxInfo]:
        findings: list[NginxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, NginxInfo(path=rel)

        info = NginxInfo(path=rel, lines=len(raw_lines))
        has_hsts = False
        has_xframe = False
        has_xcontent = False
        has_ssl_listener = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("server "):
                info.server_blocks += 1

            if WEAK_TLS_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="weak_tls",
                        severity="high",
                        message="ssl_protocols includes TLSv1 or TLSv1.1 — use TLSv1.2+",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SERVER_TOKENS_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="server_tokens_on",
                        severity="low",
                        message="server_tokens on leaks Nginx version in headers",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTOINDEX_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="autoindex_on",
                        severity="medium",
                        message="autoindex on exposes directory listings",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_CORS_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="wildcard_cors",
                        severity="medium",
                        message="wildcard CORS (Access-Control-Allow-Origin: *) is overly permissive",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_PROXY_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="insecure_proxy_pass",
                        severity="medium",
                        message="proxy_pass uses http:// — prefer https:// upstream",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SSL_VERIFY_OFF_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="ssl_verify_off",
                        severity="high",
                        message="proxy_ssl_verify off disables upstream TLS verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if "ssl_certificate" in line.lower():
                info.has_ssl = True

            if HSTS_MISSING_CONTEXT.search(line):
                has_ssl_listener = True

            if HSTS_HEADER_PATTERN.search(line):
                has_hsts = True

            if X_FRAME_OPTIONS_PATTERN.search(line):
                has_xframe = True

            if X_CONTENT_TYPE_PATTERN.search(line):
                has_xcontent = True

        if has_ssl_listener and not has_hsts:
            findings.append(
                NginxFinding(
                    kind="missing_hsts",
                    severity="medium",
                    message="HTTPS server block without Strict-Transport-Security header",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.server_blocks > 0 and not has_xframe:
            findings.append(
                NginxFinding(
                    kind="missing_x_frame_options",
                    severity="low",
                    message="no X-Frame-Options header configured",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.server_blocks > 0 and not has_xcontent:
            findings.append(
                NginxFinding(
                    kind="missing_x_content_type",
                    severity="low",
                    message="no X-Content-Type-Options header configured",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[NginxFinding]:
        """Scan Nginx configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NginxFinding] = []
        infos: list[NginxInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = NginxStats(
            configs=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NginxStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NginxInfo]:
        """Return parsed Nginx metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
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
        """Scaffold a hardened Nginx server block template."""
        return """\
# Generated by DevAI NginxAnalyzer
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass https://upstream:8443;
        proxy_ssl_verify on;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nginx configs: none found"
        return (
            f"Nginx configs: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Nginx analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {info.server_blocks} server block(s), "
                f"ssl={'yes' if info.has_ssl else 'no'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
