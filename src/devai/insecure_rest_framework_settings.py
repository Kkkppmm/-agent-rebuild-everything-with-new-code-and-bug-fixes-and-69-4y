"""InsecureRestFrameworkSettingsAnalyzer — detect insecure Django REST Framework configuration."""

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
        "rest_framework.py",
    }
)
_ALLOW_ANY_RE = re.compile(
    r"rest_framework\.permissions\.AllowAny|['\"]rest_framework\.permissions\.AllowAny['\"]",
    re.IGNORECASE,
)
_BROWSABLE_RENDERER_RE = re.compile(
    r"rest_framework\.renderers\.BrowsableAPIRenderer|BrowsableAPIRenderer",
    re.IGNORECASE,
)
_EMPTY_AUTH_CLASSES_RE = re.compile(
    r"DEFAULT_AUTHENTICATION_CLASSES\s*:\s*\[\s*\]|DEFAULT_AUTHENTICATION_CLASSES\s*=\s*\[\s*\]",
    re.IGNORECASE,
)
_EMPTY_THROTTLE_CLASSES_RE = re.compile(
    r"DEFAULT_THROTTLE_CLASSES\s*:\s*\[\s*\]|DEFAULT_THROTTLE_CLASSES\s*=\s*\[\s*\]",
    re.IGNORECASE,
)


@dataclass
class InsecureRestFrameworkSettingsFinding:
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
class InsecureRestFrameworkSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _list_string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    values: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            values.append(elt.value)
    return values


def _contains_allow_any(values: list[str]) -> bool:
    return any("allowany" in value.lower().replace("_", "") for value in values)


def _contains_browsable_renderer(values: list[str]) -> bool:
    return any("browsableapirenderer" in value.lower().replace("_", "") for value in values)


class _InsecureRestFrameworkSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureRestFrameworkSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureRestFrameworkSettingsFinding(
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
            if isinstance(target, ast.Name) and target.id == "REST_FRAMEWORK":
                if isinstance(node.value, ast.Dict):
                    self._scan_rest_framework_dict(node.value)
        self.generic_visit(node)

    def _scan_rest_framework_dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue

            if key == "DEFAULT_PERMISSION_CLASSES":
                permissions = _list_string_values(value_node)
                if _contains_allow_any(permissions):
                    self._add(
                        node.lineno,
                        "allow_any_default",
                        "high",
                        "REST_FRAMEWORK defaults to AllowAny — restrict API access with authentication",
                        setting="REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']",
                    )
            elif key == "DEFAULT_AUTHENTICATION_CLASSES":
                if isinstance(value_node, ast.List) and not value_node.elts:
                    self._add(
                        node.lineno,
                        "no_authentication_classes",
                        "high",
                        "REST_FRAMEWORK has no authentication classes — APIs accept unauthenticated requests",
                        setting="REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']",
                    )
            elif key == "DEFAULT_RENDERER_CLASSES":
                renderers = _list_string_values(value_node)
                if _contains_browsable_renderer(renderers):
                    self._add(
                        node.lineno,
                        "browsable_api_in_production",
                        "medium",
                        "BrowsableAPIRenderer enabled in production — disable browsable API to reduce attack surface",
                        setting="REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES']",
                    )
            elif key == "DEFAULT_THROTTLE_CLASSES":
                if isinstance(value_node, ast.List) and not value_node.elts:
                    self._add(
                        node.lineno,
                        "missing_throttle_classes",
                        "medium",
                        "REST_FRAMEWORK has no throttle classes — APIs are vulnerable to abuse and DoS",
                        setting="REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES']",
                    )


class InsecureRestFrameworkSettingsAnalyzer:
    """Detect insecure Django REST Framework configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureRestFrameworkSettingsFinding] = []
        self._stats: InsecureRestFrameworkSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureRestFrameworkSettingsFinding]:
        findings: list[InsecureRestFrameworkSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureRestFrameworkSettingsVisitor(rel, filename)
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
            if _ALLOW_ANY_RE.search(line) and "REST_FRAMEWORK" in source:
                findings.append(
                    InsecureRestFrameworkSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="allow_any_default",
                        severity="high",
                        message="REST_FRAMEWORK defaults to AllowAny — restrict API access with authentication",
                        setting="REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']",
                    )
                )
            if _BROWSABLE_RENDERER_RE.search(line):
                findings.append(
                    InsecureRestFrameworkSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="browsable_api_in_production",
                        severity="medium",
                        message="BrowsableAPIRenderer enabled in production — disable browsable API to reduce attack surface",
                        setting="REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES']",
                    )
                )
            if _EMPTY_AUTH_CLASSES_RE.search(line):
                findings.append(
                    InsecureRestFrameworkSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="no_authentication_classes",
                        severity="high",
                        message="REST_FRAMEWORK has no authentication classes — APIs accept unauthenticated requests",
                        setting="REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']",
                    )
                )
            if _EMPTY_THROTTLE_CLASSES_RE.search(line):
                findings.append(
                    InsecureRestFrameworkSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="missing_throttle_classes",
                        severity="medium",
                        message="REST_FRAMEWORK has no throttle classes — APIs are vulnerable to abuse and DoS",
                        setting="REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES']",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureRestFrameworkSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureRestFrameworkSettingsFinding] = []
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
        self._stats = InsecureRestFrameworkSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureRestFrameworkSettingsStats:
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
            f"Insecure REST framework settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure REST framework settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure REST framework configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
