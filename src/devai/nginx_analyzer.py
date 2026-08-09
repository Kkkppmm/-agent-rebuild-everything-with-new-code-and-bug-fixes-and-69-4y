"""NginxAnalyzer — audit Nginx configs for security and reverse-proxy best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NGINX_NAMES = ("nginx.conf",)
NGINX_SUFFIXES = (".conf",)
NGINX_DIR_NAMES = ("nginx", "conf.d", "sites-available", "sites-enabled")

SSL_PROTOCOLS_WEAK_PATTERN = re.compile(
    r"ssl_protocols\s+[^;]*(SSLv2|SSLv3|TLSv1\s|TLSv1\.0|TLSv1\.1)",
    re.IGNORECASE,
)
SERVER_TOKENS_ON_PATTERN = re.compile(r"server_tokens\s+on\b", re.IGNORECASE)
WILDCARD_CORS_PATTERN = re.compile(
    r"add_header\s+Access-Control-Allow-Origin\s+[\"']?\*[\"']?",
    re.IGNORECASE,
)
INSECURE_PROXY_PASS_PATTERN = re.compile(
    r"proxy_pass\s+http://[^\s;]+;",
    re.IGNORECASE,
)
AUTOINDEX_ON_PATTERN = re.compile(r"autoindex\s+on\b", re.IGNORECASE)
MISSING_SECURITY_HEADERS = {
    "X-Frame-Options": re.compile(r"add_header\s+X-Frame-Options\b", re.IGNORECASE),
    "X-Content-Type-Options": re.compile(
        r"add_header\s+X-Content-Type-Options\b", re.IGNORECASE
    ),
    "Strict-Transport-Security": re.compile(
        r"add_header\s+Strict-Transport-Security\b", re.IGNORECASE
    ),
}
SSL_OFF_PATTERN = re.compile(r"ssl\s+off\b", re.IGNORECASE)
ALLOW_ALL_PATTERN = re.compile(r"allow\s+all\b", re.IGNORECASE)


@dataclass
class NginxFinding:
    """A security or best-practice issue in an Nginx config."""

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
    """Parsed metadata about an Nginx config file."""

    path: str
    server_blocks: int = 0
    has_ssl: bool = False
    lines: int = 0


@dataclass
class NginxStats:
    """Aggregate Nginx config analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nginx_config(path: Path) -> bool:
    name = path.name.lower()
    if name in ("nginx.conf",) or name.endswith(".conf"):
        parts_lower = {p.lower() for p in path.parts}
        if parts_lower & set(NGINX_DIR_NAMES):
            return True
        if name == "nginx.conf":
            return True
        if "nginx" in name:
            return True
    return False


class NginxAnalyzer:
    """Audit Nginx configs for security risks and reverse-proxy best practices.

    Scans for weak TLS protocols, missing security headers, wildcard CORS,
    insecure proxy_pass, autoindex, and server_tokens exposure.
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
        content = "\n".join(raw_lines)
        found_headers: set[str] = set()

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("server "):
                info.server_blocks += 1

            if "ssl_certificate" in line or "listen 443" in line:
                info.has_ssl = True

            for header_name, pattern in MISSING_SECURITY_HEADERS.items():
                if pattern.search(line):
                    found_headers.add(header_name)

            if SSL_PROTOCOLS_WEAK_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="weak_tls",
                        severity="high",
                        message="weak TLS protocol enabled — use TLSv1.2+ only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SERVER_TOKENS_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="server_tokens",
                        severity="low",
                        message="server_tokens on exposes Nginx version in headers",
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

            if INSECURE_PROXY_PASS_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="insecure_proxy_pass",
                        severity="medium",
                        message="proxy_pass uses plain HTTP — use HTTPS upstream",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTOINDEX_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="autoindex",
                        severity="medium",
                        message="autoindex on exposes directory listings",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SSL_OFF_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="ssl_disabled",
                        severity="high",
                        message="SSL explicitly disabled on a server block",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_ALL_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="allow_all",
                        severity="medium",
                        message="allow all permits unrestricted access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.has_ssl:
            for header_name in MISSING_SECURITY_HEADERS:
                if header_name not in found_headers:
                    findings.append(
                        NginxFinding(
                            kind="missing_security_header",
                            severity="low",
                            message=f"missing {header_name} security header",
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
        """Return parsed Nginx config metadata."""
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

    ssl_certificate     /etc/ssl/certs/example.crt;
    ssl_certificate_key /etc/ssl/private/example.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers           HIGH:!aNULL:!MD5;

    server_tokens off;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass https://upstream:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
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
            "Nginx config analysis:",
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
