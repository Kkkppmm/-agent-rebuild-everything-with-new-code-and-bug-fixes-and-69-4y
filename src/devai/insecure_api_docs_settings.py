"""InsecureApiDocsSettingsAnalyzer — detect exposed Swagger/OpenAPI documentation."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SETTINGS_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "spectacular.py",
    }
)
_URLS_FILENAMES = frozenset(
    {
        "urls.py",
        "api_urls.py",
        "router.py",
        "routing.py",
    }
)
_SERVE_PUBLIC_RE = re.compile(
    r"SERVE_PUBLIC\s*[:=]\s*True",
    re.IGNORECASE,
)
_SERVE_INCLUDE_SCHEMA_RE = re.compile(
    r"SERVE_INCLUDE_SCHEMA\s*[:=]\s*True",
    re.IGNORECASE,
)
_SPECTACULAR_VIEW_RE = re.compile(
    r"Spectacular(API|Swagger|Redoc)View",
    re.IGNORECASE,
)
_DRF_SCHEMA_VIEW_RE = re.compile(
    r"get_schema_view|SchemaView|swagger_ui|openapi",
    re.IGNORECASE,
)
_DRF_YASG_RE = re.compile(
    r"drf_yasg|get_schema_view|swagger_ui|redoc",
    re.IGNORECASE,
)
_PUBLIC_SCHEMA_PERMISSION_RE = re.compile(
    r"permission_classes\s*=\s*\[\s*\]|permissions\.AllowAny|AllowAny",
    re.IGNORECASE,
)
_SWAGGER_URL_RE = re.compile(
    r"['\"](swagger|openapi|redoc|api/schema|api/docs)['\"]",
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
        if self.filename in _SETTINGS_FILENAMES:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SPECTACULAR_SETTINGS":
                    if isinstance(node.value, ast.Dict):
                        self._scan_spectacular_dict(node.value)
        self.generic_visit(node)

    def _scan_spectacular_dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue
            if key == "SERVE_PUBLIC" and _is_true(value_node):
                self._add(
                    node.lineno,
                    "serve_public_enabled",
                    "high",
                    "SPECTACULAR_SETTINGS enables SERVE_PUBLIC — restrict OpenAPI schema access in production",
                    setting="SPECTACULAR_SETTINGS['SERVE_PUBLIC']",
                )
            elif key == "SERVE_INCLUDE_SCHEMA" and _is_true(value_node):
                self._add(
                    node.lineno,
                    "serve_include_schema_enabled",
                    "medium",
                    "SPECTACULAR_SETTINGS enables SERVE_INCLUDE_SCHEMA — schema may leak in API responses",
                    setting="SPECTACULAR_SETTINGS['SERVE_INCLUDE_SCHEMA']",
                )


class InsecureApiDocsSettingsAnalyzer:
    """Detect exposed Swagger/OpenAPI documentation in production settings and URL configs."""

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

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if filename in _SETTINGS_FILENAMES:
                if _SERVE_PUBLIC_RE.search(line):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="serve_public_enabled",
                            severity="high",
                            message="SPECTACULAR_SETTINGS enables SERVE_PUBLIC — restrict OpenAPI schema access in production",
                            setting="SPECTACULAR_SETTINGS['SERVE_PUBLIC']",
                        )
                    )
                if _SERVE_INCLUDE_SCHEMA_RE.search(line):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="serve_include_schema_enabled",
                            severity="medium",
                            message="SPECTACULAR_SETTINGS enables SERVE_INCLUDE_SCHEMA — schema may leak in API responses",
                            setting="SPECTACULAR_SETTINGS['SERVE_INCLUDE_SCHEMA']",
                        )
                    )

            if filename in _URLS_FILENAMES or filename.endswith("urls.py"):
                if _SPECTACULAR_VIEW_RE.search(line):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="public_schema_view",
                            severity="high",
                            message="Public Spectacular schema/Swagger/ReDoc view registered — protect API documentation endpoints",
                            setting="urlpatterns",
                        )
                    )
                if _DRF_SCHEMA_VIEW_RE.search(line) and (
                    "schema" in line.lower() or "swagger" in line.lower() or "openapi" in line.lower()
                ):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="drf_schema_view_exposed",
                            severity="medium",
                            message="DRF schema or Swagger UI endpoint exposed — verify authentication on documentation routes",
                            setting="urlpatterns",
                        )
                    )
                if _DRF_YASG_RE.search(line) and (
                    "swagger" in line.lower() or "redoc" in line.lower() or "schema" in line.lower()
                ):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="drf_yasg_exposed",
                            severity="medium",
                            message="drf-yasg Swagger/ReDoc endpoint exposed — restrict documentation access in production",
                            setting="urlpatterns",
                        )
                    )
                if _SWAGGER_URL_RE.search(line):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="swagger_url_pattern",
                            severity="medium",
                            message="URL pattern exposes swagger/openapi/redoc route — ensure documentation is not publicly accessible",
                            setting="urlpatterns",
                        )
                    )
                if _PUBLIC_SCHEMA_PERMISSION_RE.search(line) and (
                    "schema" in source.lower()
                    or "swagger" in source.lower()
                    or "spectacular" in source.lower()
                ):
                    findings.append(
                        InsecureApiDocsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="public_schema_permissions",
                            severity="high",
                            message="Schema view uses AllowAny or empty permission_classes — API documentation is publicly accessible",
                            setting="permission_classes",
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
