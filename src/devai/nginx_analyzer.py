"""NginxAnalyzer — audit Nginx configs for TLS, proxy, and security headers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NGINX_NAMES = ("nginx.conf", "default.conf", "site.conf")

SSL_DISABLED_PATTERN = re.compile(r"ssl\s+off\b", re.IGNORECASE)
WEAK_SSL_PROTOCOL_PATTERN = re.compile(r"ssl_protocols\s+.*TLSv1[^.]", re.IGNORECASE)
NO_HSTS_PATTERN = re.compile(r"add_header\s+Strict-Transport-Security", re.IGNORECASE)
NO_XFRAME_PATTERN = re.compile(r"add_header\s+X-Frame-Options", re.IGNORECASE)
NO_CSP_PATTERN = re.compile(r"add_header\s+Content-Security-Policy", re.IGNORECASE)
PROXY_PASS_HTTP_PATTERN = re.compile(r"proxy_pass\s+http://", re.IGNORECASE)
UNSAFE_PROXY_HEADER_PATTERN = re.compile(
    r"proxy_set_header\s+X-Forwarded-For\s+\$http_x_forwarded_for",
    re.IGNORECASE,
)
AUTOINDEX_ON_PATTERN = re.compile(r"autoindex\s+on\b", re.IGNORECASE)
SERVER_TOKENS_ON_PATTERN = re.compile(r"server_tokens\s+on\b", re.IGNORECASE)
SSL_CERT_MISSING_PATTERN = re.compile(r"listen\s+443\b", re.IGNORECASE)
SSL_CERT_PATTERN = re.compile(r"ssl_certificate\s+", re.IGNORECASE)
ALLOW_ALL_PATTERN = re.compile(r"allow\s+all\b", re.IGNORECASE)
DENY_NONE_PATTERN = re.compile(r"deny\s+none\b", re.IGNORECASE)


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
    """Aggregate Nginx analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nginx_file(path: Path) -> bool:
    name = path.name.lower()
    if name in NGINX_NAMES:
        return True
    if name.endswith(".nginx") or name.endswith(".nginx.conf"):
        return True
    if "nginx" in path.parts and name.endswith((".conf", ".cfg")):
        return True
    return False


class NginxAnalyzer:
    """Audit Nginx configs for TLS, proxy, and security headers."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NginxFinding] | None = None
        self._stats: NginxStats | None = None
        self._infos: list[NginxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Nginx config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_nginx_file(path):
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
        has_listen_443 = False
        has_ssl_cert = False
        has_hsts = False
        has_xframe = False
        has_csp = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("server {") or line == "server":
                info.server_blocks += 1

            if SSL_CERT_PATTERN.search(line):
                has_ssl_cert = True
                info.has_ssl = True

            if SSL_CERT_MISSING_PATTERN.search(line):
                has_listen_443 = True

            if NO_HSTS_PATTERN.search(line):
                has_hsts = True

            if NO_XFRAME_PATTERN.search(line):
                has_xframe = True

            if NO_CSP_PATTERN.search(line):
                has_csp = True

            if SSL_DISABLED_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="ssl_disabled",
                        severity="high",
                        message="SSL explicitly disabled",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if WEAK_SSL_PROTOCOL_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="weak_ssl_protocol",
                        severity="high",
                        message="Weak SSL/TLS protocol enabled (TLSv1.0/1.1)",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if PROXY_PASS_HTTP_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="proxy_pass_http",
                        severity="medium",
                        message="proxy_pass uses plain HTTP upstream",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if UNSAFE_PROXY_HEADER_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="unsafe_proxy_header",
                        severity="medium",
                        message="X-Forwarded-For forwarded without validation",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if AUTOINDEX_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="autoindex_on",
                        severity="medium",
                        message="Directory listing enabled (autoindex on)",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if SERVER_TOKENS_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="server_tokens_on",
                        severity="low",
                        message="server_tokens on exposes Nginx version",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if ALLOW_ALL_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="allow_all",
                        severity="medium",
                        message="allow all grants unrestricted access",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if DENY_NONE_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="deny_none",
                        severity="medium",
                        message="deny none allows all clients",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

        if has_listen_443 and not has_ssl_cert:
            findings.append(
                NginxFinding(
                    kind="missing_ssl_cert",
                    severity="high",
                    message="listen 443 without ssl_certificate directive",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.server_blocks > 0 and not has_hsts and info.has_ssl:
            findings.append(
                NginxFinding(
                    kind="missing_hsts",
                    severity="medium",
                    message="No Strict-Transport-Security header configured",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.server_blocks > 0 and not has_xframe:
            findings.append(
                NginxFinding(
                    kind="missing_xframe",
                    severity="low",
                    message="No X-Frame-Options header configured",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[NginxFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[NginxFinding] = []
        infos: list[NginxInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NginxInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.configs == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nginx: none found"
        return (
            f"Nginx: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Nginx config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
