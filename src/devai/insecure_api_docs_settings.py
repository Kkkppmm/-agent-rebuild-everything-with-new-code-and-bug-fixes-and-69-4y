"""InsecureApiDocsSettingsAnalyzer — detect exposed API documentation in production."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "urls.py",
        "api_urls.py",
    }
)
_SWAGGER_URL_RE = re.compile(
    r"path\s*\(\s*['\"](?:swagger|redoc|api-docs|docs|schema)(?:/)?['\"]",
    re.IGNORECASE,
)
_SPECTACULAR_VIEW_RE = re.compile(
    r"Spectacular(API|Swagger|Redoc)View|drf_spectacular",
    re.IGNORECASE,
)
_DRF_YASG_RE = re.compile(
    r"drf_yasg|get_schema_view|SchemaView|swagger_ui",
    re.IGNORECASE,
)
_SERVE_PUBLIC_RE = re.compile(
    r"['\"]SERVE_PUBLIC['\"]\s*:\s*True|SERVE_PUBLIC\s*=\s*True",
    re.IGNORECASE,
)
_SERVE_INCLUDE_SCHEMA_RE = re.compile(
    r"['\"]SERVE_INCLUDE_SCHEMA['\"]\s*:\s*True|SERVE_INCLUDE_SCHEMA\s*=\s*True",
    re.IGNORECASE,
)
_PUBLIC_SCHEMA_VIEW_RE = re.compile(
    r"get_schema_view\s*\([^)]*public\s*=\s*True",
    re.IGNORECASE,
)
_SWAGGER_NO_SESSION_AUTH_RE = re.compile(
    r"['\"]USE_SESSION_AUTH['\"]\s*:\s*False|USE_SESSION_AUTH\s*=\s*False",
    re.IGNORECASE,
)


@dataclass
class InsecureApiDocsSettingsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureApiDocsSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class _InsecureApiDocsSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureApiDocsSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureApiDocsSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "SPECTACULAR_SETTINGS":
                if isinstance(node.value, ast.Dict):
                    self._scan_spectacular_dict(node.value, node.lineno)
        self.generic_visit(node)

    def _scan_spectacular_dict(self, node: ast.Dict, lineno: int) -> None:
        for key, value in zip(node.keys, node.values):
            key_str = _dict_string_value(key) if key else None
            if key_str == "SERVE_PUBLIC" and _is_true(value):
                self._add(
                    lineno,
                    "spectacular_public_schema",
                    "high",
                    "SPECTACULAR_SETTINGS enables public schema serving — restrict in production",
                    setting="SERVE_PUBLIC",
                )
            elif key_str == "SERVE_INCLUDE_SCHEMA" and _is_true(value):
                self._add(
                    lineno,
                    "spectacular_include_schema",
                    "medium",
                    "SPECTACULAR_SETTINGS includes schema in API responses — disable in production",
                    setting="SERVE_INCLUDE_SCHEMA",
                )

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name == "get_schema_view":
            for keyword in node.keywords:
                if keyword.arg == "public" and _is_true(keyword.value):
                    self._add(
                        node.lineno,
                        "public_schema_view",
                        "high",
                        "get_schema_view(public=True) exposes API schema without authentication",
                        setting="public",
                    )

        if func_name == "path" and self.filename in {"urls.py", "api_urls.py"}:
            for arg in node.args[:2]:
                value = _dict_string_value(arg)
                if value:
                    route = value.rstrip("/").lower()
                    if route in {
                        "swagger",
                        "redoc",
                        "api-docs",
                        "docs",
                        "schema",
                        "openapi",
                    }:
                        self._add(
                            node.lineno,
                            "swagger_url_exposed",
                            "medium",
                            f"API documentation route '{value}' is exposed — protect with authentication",
                            setting=value,
                        )

        self.generic_visit(node)


class InsecureApiDocsSettingsAnalyzer:
    """Detect exposed Swagger/OpenAPI documentation configuration in production."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureApiDocsSettingsFinding] = []
        self._stats: InsecureApiDocsSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureApiDocsSettingsFinding]:
        findings: list[InsecureApiDocsSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureApiDocsSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _SWAGGER_URL_RE.search(line):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_url_exposed",
                        severity="medium",
                        message="API documentation URL is exposed — protect with authentication",
                    )
                )
            if _SPECTACULAR_VIEW_RE.search(line) and "path(" in line:
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="spectacular_ui_exposed",
                        severity="medium",
                        message="drf-spectacular UI view is routed — restrict access in production",
                    )
                )
            if _DRF_YASG_RE.search(line) and (
                "include(" in line or "path(" in line or "get_schema_view" in line
            ):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="drf_yasg_exposed",
                        severity="medium",
                        message="drf-yasg schema or UI is exposed — restrict access in production",
                    )
                )
            if _SERVE_PUBLIC_RE.search(line):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="spectacular_public_schema",
                        severity="high",
                        message="SERVE_PUBLIC=True exposes OpenAPI schema without authentication",
                        setting="SERVE_PUBLIC",
                    )
                )
            if _SERVE_INCLUDE_SCHEMA_RE.search(line):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="spectacular_include_schema",
                        severity="medium",
                        message="SERVE_INCLUDE_SCHEMA=True embeds schema in API responses",
                        setting="SERVE_INCLUDE_SCHEMA",
                    )
                )
            if _PUBLIC_SCHEMA_VIEW_RE.search(line):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="public_schema_view",
                        severity="high",
                        message="get_schema_view(public=True) exposes API schema without authentication",
                        setting="public",
                    )
                )
            if _SWAGGER_NO_SESSION_AUTH_RE.search(line):
                findings.append(
                    InsecureApiDocsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_no_session_auth",
                        severity="medium",
                        message="USE_SESSION_AUTH=False disables session auth for Swagger UI",
                        setting="USE_SESSION_AUTH",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureApiDocsSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureApiDocsSettingsFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source, path.name)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureApiDocsSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureApiDocsSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 35.0 + high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure API docs settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure API docs settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No exposed API documentation patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
