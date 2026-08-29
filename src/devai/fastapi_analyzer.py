"""FastAPIAnalyzer — audit FastAPI apps for secrets, CORS, docs exposure, and SSRF risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
FASTAPI_IMPORT_PATTERN = re.compile(r"\b(?:from\s+fastapi|import\s+fastapi|FastAPI)\b")
ENTRYPOINT_NAMES = frozenset({"main.py", "app.py", "server.py", "asgi.py", "wsgi.py"})
HTTP_CLIENT_CALLS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "request",
        "stream",
        "AsyncClient",
        "Client",
    }
)
HTTP_CLIENT_MODULES = frozenset({"httpx", "requests", "aiohttp"})


@dataclass
class FastAPIFinding:
    """A security issue in a FastAPI application."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class FastAPIInfo:
    """Parsed metadata about a FastAPI module."""

    path: str
    lines: int = 0
    routes: int = 0
    has_cors: bool = False
    has_trusted_host: bool = False
    has_https_redirect: bool = False
    uses_fastapi: bool = False


@dataclass
class FastAPIStats:
    """Aggregate FastAPI analysis statistics."""

    files: int = 0
    fastapi_files: int = 0
    routes: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_wildcard_origin(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List) and any(
        isinstance(elt, ast.Constant) and elt.value == "*" for elt in node.elts
    ):
        return True
    return False


def _kw_bool(node: ast.AST, default: bool | None = None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return default


def _kw_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_http_client_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute) and func.attr in HTTP_CLIENT_CALLS:
        if isinstance(func.value, ast.Name) and func.value.id in HTTP_CLIENT_MODULES:
            return True
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            if func.value.value.id in HTTP_CLIENT_MODULES:
                return True
    if isinstance(func, ast.Name) and func.id in {"urlopen", "Request"}:
        return True
    return False


def _is_route_decorator(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
        "websocket",
        "api_route",
    }:
        return True
    return False


class _FastAPIVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str, raw_lines: list[str]) -> None:
        self.path = path
        self.filename = filename
        self.raw_lines = raw_lines
        self.findings: list[FastAPIFinding] = []
        self.info = FastAPIInfo(path=path, lines=len(raw_lines), uses_fastapi=True)
        self._in_route_handler = False
        self._route_depth = 0
        self._has_docs_disabled = False
        self._cors_wildcard = False
        self._cors_credentials = False

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.raw_lines):
            return self.raw_lines[lineno - 1].strip()
        return ""

    def _add(
        self,
        kind: str,
        severity: str,
        message: str,
        lineno: int,
        line: str = "",
    ) -> None:
        self.findings.append(
            FastAPIFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=self.path,
                lineno=lineno,
                line=line or self._line_text(lineno),
            )
        )

    def _middleware_name(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            if func.attr == "add_middleware" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Name):
                    return first.id
                if isinstance(first, ast.Attribute):
                    return first.attr
            return func.attr
        return ""

    def _cors_keywords(self, node: ast.Call) -> list[ast.keyword]:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "add_middleware":
            return list(node.keywords)
        return list(node.keywords)

    def _check_cors_call(self, node: ast.Call) -> None:
        middleware_name = self._middleware_name(node)
        if middleware_name != "CORSMiddleware":
            return

        self.info.has_cors = True
        for kw in self._cors_keywords(node):
            if kw.arg in {"allow_origins", "origins"} and _is_wildcard_origin(kw.value):
                self._cors_wildcard = True
                self._add(
                    "cors_wildcard",
                    "high",
                    "CORSMiddleware allow_origins includes * — restrict to trusted domains",
                    node.lineno,
                )
            if kw.arg == "allow_credentials" and _kw_bool(kw.value) is True:
                self._cors_credentials = True

        if self._cors_wildcard and self._cors_credentials:
            self._add(
                "cors_credentials_wildcard",
                "high",
                "allow_credentials=True with wildcard origins is invalid and insecure",
                node.lineno,
            )

    def _check_middleware_call(self, node: ast.Call) -> None:
        middleware_name = self._middleware_name(node)

        if middleware_name == "TrustedHostMiddleware":
            self.info.has_trusted_host = True
            for kw in self._cors_keywords(node):
                if kw.arg == "allowed_hosts" and _is_wildcard_origin(kw.value):
                    self._add(
                        "trusted_host_wildcard",
                        "high",
                        "TrustedHostMiddleware allowed_hosts includes * — host header attacks possible",
                        node.lineno,
                    )

        if middleware_name == "HTTPSRedirectMiddleware":
            self.info.has_https_redirect = True

        self._check_cors_call(node)

    def _check_fastapi_ctor(self, node: ast.Call) -> None:
        func = node.func
        is_fastapi = isinstance(func, ast.Name) and func.id == "FastAPI"
        if not is_fastapi:
            return

        debug_enabled = False
        docs_disabled = False
        for kw in node.keywords:
            if kw.arg == "debug" and _kw_bool(kw.value) is True:
                debug_enabled = True
            if kw.arg in {"docs_url", "redoc_url", "openapi_url"}:
                value = _kw_str(kw.value)
                if value is None and isinstance(kw.value, ast.Constant) and kw.value.value is None:
                    docs_disabled = True
                elif kw.arg == "docs_url" and value is None:
                    docs_disabled = True

        if debug_enabled:
            self._add(
                "debug_enabled",
                "high",
                "FastAPI(debug=True) exposes tracebacks and interactive docs in production",
                node.lineno,
            )

        if self.filename in ENTRYPOINT_NAMES and not docs_disabled:
            self._add(
                "openapi_docs_exposed",
                "medium",
                "OpenAPI docs enabled on entrypoint — set docs_url=None, redoc_url=None, openapi_url=None in production",
                node.lineno,
            )

    def _check_uvicorn_run(self, node: ast.Call) -> None:
        func = node.func
        is_uvicorn = False
        if isinstance(func, ast.Attribute) and func.attr == "run":
            if isinstance(func.value, ast.Name) and func.value.id == "uvicorn":
                is_uvicorn = True
        if not is_uvicorn:
            return

        host = None
        reload = None
        for kw in node.keywords:
            if kw.arg == "host":
                host = _kw_str(kw.value)
            if kw.arg == "reload" and _kw_bool(kw.value) is True:
                reload = True

        if host == "0.0.0.0":
            self._add(
                "bind_all_interfaces",
                "medium",
                'uvicorn.run(host="0.0.0.0") binds all interfaces — restrict with firewall or reverse proxy',
                node.lineno,
            )
        if reload and self.filename in ENTRYPOINT_NAMES:
            self._add(
                "reload_in_entrypoint",
                "medium",
                "uvicorn.run(reload=True) in entrypoint — disable auto-reload in production",
                node.lineno,
            )

    def _check_http_client_ssrf(self, node: ast.Call) -> None:
        if not self._in_route_handler or not _is_http_client_call(node.func):
            return
        if not node.args:
            return
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Name):
            self._add(
                "ssrf_user_url",
                "high",
                "HTTP client called with variable URL inside route handler — SSRF risk",
                node.lineno,
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            if _is_route_decorator(decorator):
                self.info.routes += 1
                self._route_depth += 1
                self._in_route_handler = True
                break
        self.generic_visit(node)
        if self._route_depth:
            self._route_depth -= 1
            self._in_route_handler = self._route_depth > 0

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Call(self, node: ast.Call) -> None:
        self._check_fastapi_ctor(node)
        self._check_middleware_call(node)
        self._check_uvicorn_run(node)
        self._check_http_client_ssrf(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "fastapi" or alias.name.startswith("fastapi."):
                self.info.uses_fastapi = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.startswith("fastapi"):
            self.info.uses_fastapi = True
        self.generic_visit(node)

    def finalize(self) -> None:
        if self.info.uses_fastapi and not self.info.has_trusted_host and self.filename in ENTRYPOINT_NAMES:
            self._add(
                "missing_trusted_host",
                "low",
                "No TrustedHostMiddleware — add allowed_hosts to prevent host header attacks",
                1,
            )


def _uses_fastapi(source: str) -> bool:
    return bool(FASTAPI_IMPORT_PATTERN.search(source))


def _scan_line_patterns(
    line: str,
    lineno: int,
    rel: str,
    findings: list[FastAPIFinding],
) -> None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return

    checks: list[tuple[re.Pattern[str], str, str, str]] = [
        (
            HARDCODED_SECRET_PATTERN,
            "hardcoded_secret",
            "high",
            "hardcoded secret in FastAPI app — use environment variables or a secret store",
        ),
        (
            AWS_ACCESS_KEY_PATTERN,
            "aws_access_key",
            "high",
            "AWS access key in source — rotate and use IAM roles or secret stores",
        ),
        (
            INSECURE_HTTP_PATTERN,
            "insecure_http",
            "medium",
            "insecure HTTP URL — use HTTPS for external services",
        ),
    ]
    for pattern, kind, severity, message in checks:
        if pattern.search(line):
            findings.append(
                FastAPIFinding(
                    kind=kind,
                    severity=severity,
                    message=message,
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )


class FastAPIAnalyzer:
    """Audit FastAPI applications for secrets, CORS, docs exposure, SSRF, and production risks.

    Scans Python modules that import FastAPI for hardcoded credentials, wildcard CORS,
    exposed OpenAPI docs, debug mode, uvicorn reload, missing TrustedHostMiddleware,
    and user-controlled HTTP client URLs in route handlers.
    """

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[FastAPIFinding] | None = None
        self._stats: FastAPIStats | None = None
        self._infos: list[FastAPIInfo] | None = None

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def files(self) -> list[Path]:
        """Return Python files in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if path.is_file() and not self._should_skip(path):
                found.append(path)
        return found

    def fastapi_files(self) -> list[Path]:
        """Return Python files that appear to use FastAPI."""
        result: list[Path] = []
        for path in self.files():
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _uses_fastapi(source):
                result.append(path)
        return result

    def _analyze_file(self, path: Path) -> tuple[list[FastAPIFinding], FastAPIInfo | None]:
        rel = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], None

        if not _uses_fastapi(source):
            return [], None

        raw_lines = source.splitlines()
        findings: list[FastAPIFinding] = []
        for lineno, raw in enumerate(raw_lines, start=1):
            _scan_line_patterns(raw, lineno, rel, findings)

        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            info = FastAPIInfo(path=rel, lines=len(raw_lines), uses_fastapi=True)
            return findings, info

        visitor = _FastAPIVisitor(rel, path.name, raw_lines)
        visitor.visit(tree)
        visitor.finalize()
        findings.extend(visitor.findings)
        return findings, visitor.info

    def analyze(self) -> list[FastAPIFinding]:
        """Scan FastAPI modules and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FastAPIFinding] = []
        infos: list[FastAPIInfo] = []
        paths = self.files()
        fastapi_count = 0
        route_count = 0

        for path in paths:
            file_findings, info = self._analyze_file(path)
            if info is None:
                continue
            fastapi_count += 1
            route_count += info.routes
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = FastAPIStats(
            files=len(paths),
            fastapi_files=fastapi_count,
            routes=route_count,
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FastAPIStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FastAPIInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.fastapi_files == 0:
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
        """Scaffold a hardened FastAPI application template."""
        return """\
# Generated by DevAI FastAPIAnalyzer
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

app = FastAPI(
    title="My API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    debug=False,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
)
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "https://example.com").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.fastapi_files == 0:
            return "FastAPI: no application modules found"
        return (
            f"FastAPI: {stats.fastapi_files} module(s), {stats.routes} route(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "FastAPI analysis:",
            f"  modules: {stats.fastapi_files}",
            f"  routes: {stats.routes}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {info.routes} route(s), "
                f"cors={'yes' if info.has_cors else 'no'}, "
                f"trusted_host={'yes' if info.has_trusted_host else 'no'}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
