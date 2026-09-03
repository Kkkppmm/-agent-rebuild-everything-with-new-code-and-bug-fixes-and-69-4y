"""OpenAPIAnalyzer — audit OpenAPI/Swagger specs for security and design risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

OPENAPI_CONFIG_NAMES = (
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger.json",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|server|host|basePath|baseUrl)\s*[=:]\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+|"
    r"\"url\"\s*:\s*\"http://(?!localhost|127\.0\.0\.1)[^\"]+\"",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
API_KEY_IN_QUERY_PATTERN = re.compile(
    r"type\s*:\s*apiKey[\s\S]{0,120}?in\s*:\s*query|"
    r"\"type\"\s*:\s*\"apiKey\"[\s\S]{0,120}?\"in\"\s*:\s*\"query\"",
    re.IGNORECASE,
)
WILDCARD_CORS_PATTERN = re.compile(
    r"(?:access-control-allow-origin|Access-Control-Allow-Origin)\s*[=:]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
EMPTY_SECURITY_PATTERN = re.compile(
    r"^\s*security\s*:\s*\[\s*\]\s*$|^\s*\"security\"\s*:\s*\[\s*\]\s*,?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:/admin|/internal|/debug|/actuator|/metrics|/healthz|/swagger|/graphql|/management)(?:/|\"|\s|$)",
    re.IGNORECASE,
)
BASIC_AUTH_PATTERN = re.compile(
    r"type\s*:\s*http[\s\S]{0,80}?scheme\s*:\s*basic|"
    r"\"type\"\s*:\s*\"http\"[\s\S]{0,80}?\"scheme\"\s*:\s*\"basic\"",
    re.IGNORECASE,
)
OAUTH_IMPLICIT_PATTERN = re.compile(
    r"(?:flow\s*:\s*implicit|\"flow\"\s*:\s*\"implicit\"|^\s*implicit\s*:\s*$)",
    re.IGNORECASE | re.MULTILINE,
)
HTTP_BEARER_NO_HTTPS_PATTERN = re.compile(
    r"scheme\s*:\s*bearer[\s\S]{0,200}http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
WILDCARD_HOST_PATTERN = re.compile(
    r"(?:host|servers?)\s*[=:]\s*[\"']?\*[\"']?|"
    r"\"host\"\s*:\s*\"\*\"",
    re.IGNORECASE,
)


@dataclass
class OpenAPIFinding:
    """A security or best-practice issue in an OpenAPI specification."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class OpenAPIInfo:
    """Parsed metadata about an OpenAPI specification file."""

    path: str
    lines: int = 0
    format: str = ""
    openapi_version: str = ""
    title: str = ""
    paths: int = 0
    servers: int = 0


@dataclass
class OpenAPIStats:
    """Aggregate OpenAPI analysis statistics."""

    specs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_openapi_file(path: Path) -> bool:
    return path.name.lower() in OPENAPI_CONFIG_NAMES


def _detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    return "yaml"


def _extract_openapi_version(text: str) -> str:
    match = re.search(r'["\']?openapi["\']?\s*[=:]\s*["\']?([0-9.]+)["\']?', text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'["\']?swagger["\']?\s*[=:]\s*["\']?([0-9.]+)["\']?', text, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_title(text: str) -> str:
    match = re.search(
        r'["\']?title["\']?\s*[=:]\s*["\']?([^"\'\n]+?)["\']?\s*$',
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def _count_paths(text: str) -> int:
    return len(re.findall(r'^\s{0,4}/[^\s:]+:\s*$', text, re.MULTILINE))


def _count_servers(text: str) -> int:
    return len(re.findall(r'^\s*-?\s*url\s*:', text, re.MULTILINE | re.IGNORECASE))


class OpenAPIAnalyzer:
    """Audit OpenAPI/Swagger specifications for security issues.

    Scans openapi.yaml/json and swagger.yaml/json for insecure HTTP servers,
    credentials in URLs, hardcoded secrets, API keys in query parameters,
    wildcard CORS, empty global security, sensitive unauthenticated paths,
    deprecated OAuth implicit flows, and wildcard hosts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[OpenAPIFinding] | None = None
        self._stats: OpenAPIStats | None = None
        self._infos: list[OpenAPIInfo] | None = None

    def specs(self) -> list[Path]:
        """Return OpenAPI/Swagger specification paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_openapi_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[OpenAPIFinding],
        full_text: str,
    ) -> None:
        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in OpenAPI spec — use environment variables or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in OpenAPI spec — remove credentials from API documentation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="insecure_http_server",
                    severity="medium",
                    message="insecure HTTP server URL — document HTTPS endpoints in production specs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="credentials_in_url",
                    severity="high",
                    message="credentials embedded in server URL — remove secrets from spec files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_CORS_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="wildcard_cors",
                    severity="medium",
                    message="wildcard CORS origin in spec — restrict allowed origins in production APIs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_HOST_PATTERN.search(line):
            findings.append(
                OpenAPIFinding(
                    kind="wildcard_host",
                    severity="low",
                    message="wildcard host in spec — pin server URLs to known environments",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line) and "security" not in line.lower():
            findings.append(
                OpenAPIFinding(
                    kind="sensitive_path",
                    severity="medium",
                    message="sensitive path in spec — ensure admin/debug endpoints require authentication",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _scan_document(self, text: str, rel: str, findings: list[OpenAPIFinding]) -> None:
        if API_KEY_IN_QUERY_PATTERN.search(text):
            findings.append(
                OpenAPIFinding(
                    kind="api_key_in_query",
                    severity="medium",
                    message="API key transmitted in query string — prefer Authorization header",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if EMPTY_SECURITY_PATTERN.search(text):
            findings.append(
                OpenAPIFinding(
                    kind="empty_global_security",
                    severity="medium",
                    message="global security set to empty array — endpoints may be unauthenticated by default",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if BASIC_AUTH_PATTERN.search(text) and INSECURE_HTTP_PATTERN.search(text):
            findings.append(
                OpenAPIFinding(
                    kind="basic_auth_over_http",
                    severity="high",
                    message="HTTP basic auth over insecure HTTP — use HTTPS for credential-based auth",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if OAUTH_IMPLICIT_PATTERN.search(text):
            findings.append(
                OpenAPIFinding(
                    kind="oauth_implicit_flow",
                    severity="medium",
                    message="OAuth implicit flow documented — prefer authorization code flow with PKCE",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if HTTP_BEARER_NO_HTTPS_PATTERN.search(text):
            findings.append(
                OpenAPIFinding(
                    kind="bearer_over_http",
                    severity="high",
                    message="bearer token auth with HTTP server — use HTTPS for token-based APIs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[OpenAPIFinding], OpenAPIInfo]:
        findings: list[OpenAPIFinding] = []
        rel = str(path.relative_to(self.root))
        file_format = _detect_format(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, OpenAPIInfo(path=rel, format=file_format)

        if file_format == "json":
            try:
                json.loads(text)
            except json.JSONDecodeError:
                findings.append(
                    OpenAPIFinding(
                        kind="invalid_json",
                        severity="low",
                        message="invalid JSON OpenAPI spec — fix syntax before publishing",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        raw_lines = text.splitlines()
        info = OpenAPIInfo(
            path=rel,
            lines=len(raw_lines),
            format=file_format,
            openapi_version=_extract_openapi_version(text),
            title=_extract_title(text),
            paths=_count_paths(text),
            servers=_count_servers(text),
        )

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, text)

        self._scan_document(text, rel, findings)
        return findings, info

    def analyze(self) -> list[OpenAPIFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[OpenAPIFinding] = []
        infos: list[OpenAPIInfo] = []
        paths = self.specs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = OpenAPIStats(
            specs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> OpenAPIStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[OpenAPIInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.specs == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_snippet(self) -> str:
        """Scaffold a hardened OpenAPI security snippet."""
        return """\
# OpenAPI security hardening checklist
# - Use HTTPS server URLs in production specs
# - Define global security requirements (do not set security: [])
# - Put API keys in headers, not query parameters
# - Avoid OAuth implicit flow; use authorization code + PKCE
# - Do not embed credentials in server URLs
# - Restrict CORS origins; avoid Access-Control-Allow-Origin: *
# - Require auth on /admin, /debug, /internal, and /actuator paths
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.specs == 0:
            return "OpenAPI specs: none found"
        return (
            f"OpenAPI specs: {stats.specs} spec(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "OpenAPI analysis:",
            f"  specs: {stats.specs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.format}, OpenAPI {info.openapi_version or 'unknown'}): "
                f"{info.paths} path(s), {info.servers} server(s)"
            )
            if info.title:
                lines.append(f"    title: {info.title}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
