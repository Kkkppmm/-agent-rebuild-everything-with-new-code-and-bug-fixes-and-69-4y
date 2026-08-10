"""InsecureSwaggerSettingsAnalyzer — detect exposed API documentation in production."""

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
        "swagger.py",
        "openapi.py",
    }
)
_SWAGGER_PUBLIC_RE = re.compile(
    r"(SWAGGER_SETTINGS|SPECTACULAR_SETTINGS)\s*=\s*\{[^}]*['\"]SERVE_PUBLIC['\"]\s*:\s*True",
    re.IGNORECASE,
)
_SCHEMA_PUBLIC_RE = re.compile(
    r"(SERVE_INCLUDE_SCHEMA|SERVE_SCHEMA)\s*=\s*True",
    re.IGNORECASE,
)
_SWAGGER_UI_RE = re.compile(
    r"(SWAGGER_UI_ENABLED|ENABLE_SWAGGER|DRF_YASG_ENABLED)\s*=\s*True",
    re.IGNORECASE,
)
_OPENAPI_URL_RE = re.compile(
    r"path\(['\"]swagger|path\(['\"]api/docs|path\(['\"]redoc",
    re.IGNORECASE,
)


@dataclass
class InsecureSwaggerSettingsFinding:
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
class InsecureSwaggerSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _dict_bool_true(node: ast.AST, key: str) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for k, v in zip(node.keys, node.values):
        if (
            k
            and isinstance(k, ast.Constant)
            and isinstance(k.value, str)
            and k.value.upper() == key.upper()
            and _bool_value(v) is True
        ):
            return True
    return False


class _InsecureSwaggerSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureSwaggerSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureSwaggerSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id.upper()
            if name in {"SWAGGER_SETTINGS", "SPECTACULAR_SETTINGS"}:
                if _dict_bool_true(node.value, "SERVE_PUBLIC"):
                    self._add(
                        node.lineno,
                        "swagger_public_access",
                        "high",
                        f"{target.id} SERVE_PUBLIC is True — API schema is exposed without authentication",
                        setting=target.id,
                    )
                if _dict_bool_true(node.value, "SERVE_INCLUDE_SCHEMA"):
                    self._add(
                        node.lineno,
                        "swagger_schema_exposed",
                        "medium",
                        f"{target.id} SERVE_INCLUDE_SCHEMA is True — schema endpoint is publicly accessible",
                        setting=target.id,
                    )
            elif name in {"SERVE_INCLUDE_SCHEMA", "SERVE_SCHEMA", "SWAGGER_UI_ENABLED", "ENABLE_SWAGGER"}:
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "swagger_ui_enabled",
                        "medium",
                        f"{target.id} is enabled — disable interactive API docs in production",
                        setting=target.id,
                    )
            elif name == "DRF_YASG_ENABLED":
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "swagger_ui_enabled",
                        "medium",
                        "DRF_YASG_ENABLED is True — disable Swagger UI in production",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureSwaggerSettingsAnalyzer:
    """Detect exposed Swagger/OpenAPI documentation in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureSwaggerSettingsFinding] = []
        self._stats: InsecureSwaggerSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureSwaggerSettingsFinding]:
        findings: list[InsecureSwaggerSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureSwaggerSettingsVisitor(rel, filename)
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
            if _SWAGGER_PUBLIC_RE.search(line):
                findings.append(
                    InsecureSwaggerSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_public_access",
                        severity="high",
                        message="API schema SERVE_PUBLIC is True — schema is exposed without authentication",
                        setting="SPECTACULAR_SETTINGS",
                    )
                )
            if _SCHEMA_PUBLIC_RE.search(line):
                findings.append(
                    InsecureSwaggerSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_schema_exposed",
                        severity="medium",
                        message="Schema endpoint is publicly accessible — restrict in production",
                        setting="SERVE_INCLUDE_SCHEMA",
                    )
                )
            if _SWAGGER_UI_RE.search(line):
                findings.append(
                    InsecureSwaggerSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_ui_enabled",
                        severity="medium",
                        message="Interactive API documentation is enabled — disable in production",
                        setting="SWAGGER_UI_ENABLED",
                    )
                )
            if _OPENAPI_URL_RE.search(line):
                findings.append(
                    InsecureSwaggerSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="swagger_url_exposed",
                        severity="medium",
                        message="Swagger/OpenAPI URL route is exposed — protect or remove in production",
                        setting="urls",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureSwaggerSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureSwaggerSettingsFinding] = []
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
        self._stats = InsecureSwaggerSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureSwaggerSettingsStats:
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
            f"Insecure Swagger settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Swagger settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Swagger/OpenAPI configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
