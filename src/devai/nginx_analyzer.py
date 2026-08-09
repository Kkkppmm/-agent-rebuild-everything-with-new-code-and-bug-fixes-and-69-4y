"""NginxAnalyzer — audit Nginx configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NGINX_NAMES = ("nginx.conf",)
NGINX_SUFFIXES = (".conf",)
NGINX_DIRS = ("nginx", "conf.d", "sites-enabled", "sites-available")

WEAK_SSL_PROTOCOL_PATTERN = re.compile(
    r"ssl_protocols\s+[^;]*\b(TLSv1\.1|TLSv1(?!\.\d)|SSLv3|SSLv2)\b",
    re.IGNORECASE,
)
WEAK_CIPHER_PATTERN = re.compile(
    r"ssl_ciphers\s+[^;]*(?<!!)\b(NULL|EXPORT|RC4|DES|MD5|anon)\b",
    re.IGNORECASE,
)
SERVER_TOKENS_ON_PATTERN = re.compile(r"server_tokens\s+on\b", re.IGNORECASE)
AUTOINDEX_ON_PATTERN = re.compile(r"autoindex\s+on\b", re.IGNORECASE)
INSECURE_PROXY_PATTERN = re.compile(
    r"proxy_pass\s+http://(?!127\.0\.0\.1|localhost)",
    re.IGNORECASE,
)
WILDCARD_CORS_PATTERN = re.compile(
    r"add_header\s+Access-Control-Allow-Origin\s+['\"]?\*['\"]?",
    re.IGNORECASE,
)
STUB_STATUS_PATTERN = re.compile(r"stub_status\b", re.IGNORECASE)
ALLOW_ALL_PATTERN = re.compile(r"^\s*allow\s+all\s*;", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s+",
    re.IGNORECASE,
)
IF_DIRECTIVE_PATTERN = re.compile(r"^\s*if\s*\(", re.IGNORECASE)
LISTEN_443_NO_SSL_PATTERN = re.compile(
    r"listen\s+[^;]*443(?!.*\bssl\b)[^;]*;",
    re.IGNORECASE,
)
SSL_LISTEN_PATTERN = re.compile(r"listen\s+[^;]*\bssl\b", re.IGNORECASE)
SSL_CERT_PATTERN = re.compile(r"ssl_certificate\s+", re.IGNORECASE)
HSTS_PATTERN = re.compile(
    r"add_header\s+Strict-Transport-Security\b",
    re.IGNORECASE,
)
X_FRAME_PATTERN = re.compile(
    r"add_header\s+X-Frame-Options\b",
    re.IGNORECASE,
)
DENY_DOTFILES_PATTERN = re.compile(
    r"location\s+[^;{]*\\?\.\s",
    re.IGNORECASE,
)
DANGEROUS_ALIAS_PATTERN = re.compile(
    r"alias\s+['\"]?(?:/|/etc|/proc|/sys)['\"]?",
    re.IGNORECASE,
)


@dataclass
class NginxFinding:
    """A security or best-practice issue in an Nginx config file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    server: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        srv = f" ({self.server})" if self.server else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{srv} — {self.message}"


@dataclass
class NginxInfo:
    """Parsed metadata about an Nginx config file."""

    path: str
    servers: list[str] = field(default_factory=list)
    has_ssl: bool = False
    has_upstream: bool = False
    lines: int = 0


@dataclass
class NginxStats:
    """Aggregate Nginx analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nginx_config(path: Path) -> bool:
    name = path.name.lower()
    if name in NGINX_NAMES:
        return True
    if name.endswith(NGINX_SUFFIXES):
        parent_parts = {p.lower() for p in path.parts}
        if parent_parts & set(NGINX_DIRS):
            return True
        if "nginx" in name:
            return True
        if name in ("default.conf", "site.conf", "app.conf"):
            return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class NginxAnalyzer:
    """Audit Nginx configuration files for security risks and reverse-proxy best practices.

    Scans for weak TLS settings, information disclosure, insecure proxy_pass targets,
    wildcard CORS, missing security headers, and other common misconfigurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NginxFinding] | None = None
        self._stats: NginxStats | None = None
        self._infos: list[NginxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Nginx configuration file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_nginx_config(path):
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
        current_server = ""
        in_server = False
        server_has_ssl_listen = False
        server_has_ssl_cert = False
        server_has_hsts = False
        server_has_x_frame = False
        file_has_stub_status = False
        file_has_access_control = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.startswith("server ") and line.rstrip().endswith("{"):
                in_server = True
                current_server = f"server@{lineno}"
                info.servers.append(current_server)
                server_has_ssl_listen = False
                server_has_ssl_cert = False
                server_has_hsts = False
                server_has_x_frame = False
                continue

            if in_server and line == "}":
                if server_has_ssl_listen and not server_has_ssl_cert:
                    findings.append(
                        NginxFinding(
                            kind="ssl_listen_no_cert",
                            severity="high",
                            message=(
                                "server listens with SSL but has no ssl_certificate directive"
                            ),
                            path=rel,
                            lineno=lineno,
                            server=current_server,
                        )
                    )
                if server_has_ssl_listen and not server_has_hsts:
                    findings.append(
                        NginxFinding(
                            kind="missing_hsts",
                            severity="medium",
                            message=(
                                "HTTPS server missing Strict-Transport-Security header"
                            ),
                            path=rel,
                            lineno=lineno,
                            server=current_server,
                        )
                    )
                if not server_has_x_frame:
                    findings.append(
                        NginxFinding(
                            kind="missing_x_frame_options",
                            severity="low",
                            message="server block missing X-Frame-Options header",
                            path=rel,
                            lineno=lineno,
                            server=current_server,
                        )
                    )
                in_server = False
                current_server = ""
                continue

            if WEAK_SSL_PROTOCOL_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="weak_ssl_protocol",
                        severity="high",
                        message="ssl_protocols includes deprecated TLS versions",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if WEAK_CIPHER_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="weak_cipher",
                        severity="high",
                        message="ssl_ciphers includes weak or null ciphers",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if SERVER_TOKENS_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="server_tokens_on",
                        severity="low",
                        message="server_tokens on exposes Nginx version in responses",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if AUTOINDEX_ON_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="autoindex_on",
                        severity="medium",
                        message="autoindex on enables directory listing",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if INSECURE_PROXY_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="insecure_proxy_pass",
                        severity="medium",
                        message="proxy_pass uses plain http:// upstream",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )
                info.has_upstream = True

            if WILDCARD_CORS_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="wildcard_cors",
                        severity="medium",
                        message="Access-Control-Allow-Origin * permits any origin",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if STUB_STATUS_PATTERN.search(line):
                file_has_stub_status = True

            if ALLOW_ALL_PATTERN.match(line):
                findings.append(
                    NginxFinding(
                        kind="allow_all",
                        severity="medium",
                        message="allow all grants unrestricted access to this context",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if re.search(r"\b(allow|deny)\s+", line, re.IGNORECASE):
                file_has_access_control = True

            if SECRET_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="secret_in_config",
                        severity="high",
                        message=(
                            "potential secret in config — use env vars or include "
                            "restricted files"
                        ),
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if IF_DIRECTIVE_PATTERN.match(line):
                findings.append(
                    NginxFinding(
                        kind="if_directive",
                        severity="low",
                        message="if directive in Nginx is error-prone — prefer map/limit_req",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if LISTEN_443_NO_SSL_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="listen_443_no_ssl",
                        severity="high",
                        message="listen on port 443 without ssl flag",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if SSL_LISTEN_PATTERN.search(line):
                server_has_ssl_listen = True
                info.has_ssl = True

            if SSL_CERT_PATTERN.search(line):
                server_has_ssl_cert = True

            if HSTS_PATTERN.search(line):
                server_has_hsts = True

            if X_FRAME_PATTERN.search(line):
                server_has_x_frame = True

            if DANGEROUS_ALIAS_PATTERN.search(line):
                findings.append(
                    NginxFinding(
                        kind="dangerous_alias",
                        severity="high",
                        message="alias points to sensitive host path",
                        path=rel,
                        lineno=lineno,
                        server=current_server,
                        line=raw.strip(),
                    )
                )

            if line.startswith("upstream "):
                info.has_upstream = True

        if file_has_stub_status and not file_has_access_control:
            findings.append(
                NginxFinding(
                    kind="unrestricted_stub_status",
                    severity="medium",
                    message="stub_status without allow/deny access controls",
                    path=rel,
                    lineno=info.lines,
                )
            )

        if not any(DENY_DOTFILES_PATTERN.search(_strip_comment(r)) for r in raw_lines):
            if any("location" in _strip_comment(r) for r in raw_lines):
                findings.append(
                    NginxFinding(
                        kind="no_dotfile_protection",
                        severity="low",
                        message=(
                            "no location block denying dotfiles (e.g. location ~ /\\.)"
                        ),
                        path=rel,
                        lineno=1,
                    )
                )

        return findings, info

    def analyze(self) -> list[NginxFinding]:
        """Scan Nginx config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NginxFinding] = []
        infos: list[NginxInfo] = []
        paths = self.config_files()

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
            config_files=len(paths),
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
        """Return a 0-100 health score (100 = no issues or no config files)."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened Nginx reverse-proxy template."""
        return """\
# Generated by DevAI NginxAnalyzer
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.crt;
    ssl_certificate_key /etc/ssl/private/example.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ~ /\\. {
        deny all;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
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
        if stats.config_files == 0:
            return "Nginx configs: none found"
        lines = [
            (
                f"Nginx configs: {stats.config_files} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        lines = [
            "# Nginx Configuration Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                ssl = "ssl" if info.has_ssl else "no-ssl"
                lines.append(
                    f"- {info.path}: {len(info.servers)} server(s), {ssl}, "
                    f"{info.lines} lines"
                )
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
