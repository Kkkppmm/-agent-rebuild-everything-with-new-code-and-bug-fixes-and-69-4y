"""CorsMisconfigAnalyzer — detect overly permissive CORS configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WILDCARD_ORIGIN = re.compile(
    r"""(?:origins|allow_origins|cors_allowed_origins|CORS_ORIGINS)\s*=\s*["']\*["']""",
    re.IGNORECASE,
)
_WILDCARD_LIST = re.compile(
    r"""(?:origins|allow_origins|cors_allowed_origins)\s*=\s*\[\s*["']\*["']\s*\]""",
    re.IGNORECASE,
)


@dataclass
class CorsMisconfigFinding:
    """A potentially unsafe CORS configuration."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class CorsMisconfigStats:
    """Aggregate CORS misconfiguration statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_wildcard_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List) and node.elts:
        return all(isinstance(elt, ast.Constant) and elt.value == "*" for elt in node.elts)
    return False


class _CorsVisitor(ast.NodeVisitor):
    """Walk a module AST and collect CORS misconfigurations."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CorsMisconfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name == "CORS":
            for kw in node.keywords:
                if kw.arg in {"origins", "resources"} and _is_wildcard_value(kw.value):
                    self.findings.append(
                        CorsMisconfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="flask_cors_wildcard",
                            severity="high",
                            message="flask-cors with wildcard origins allows any site to call your API",
                            function=self._current_function(),
                        )
                    )
                if kw.arg == "resources" and isinstance(kw.value, ast.Dict):
                    for val in kw.value.values:
                        if _is_wildcard_value(val):
                            self.findings.append(
                                CorsMisconfigFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="flask_cors_resource_wildcard",
                                    severity="high",
                                    message="flask-cors resource map uses wildcard origin",
                                    function=self._current_function(),
                                )
                            )

        if name == "CORSMiddleware":
            for kw in node.keywords:
                if kw.arg == "allow_origins" and _is_wildcard_value(kw.value):
                    self.findings.append(
                        CorsMisconfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="fastapi_cors_wildcard",
                            severity="high",
                            message="FastAPI CORSMiddleware with allow_origins=['*'] is overly permissive",
                            function=self._current_function(),
                        )
                    )

        if isinstance(func, ast.Attribute) and func.attr == "add_middleware":
            middleware_name = ""
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.Name):
                    middleware_name = first.id
                elif isinstance(first, ast.Attribute):
                    middleware_name = first.attr
            if middleware_name == "CORSMiddleware":
                for kw in node.keywords:
                    if kw.arg == "allow_origins" and _is_wildcard_value(kw.value):
                        self.findings.append(
                            CorsMisconfigFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="fastapi_cors_wildcard",
                                severity="high",
                                message="FastAPI CORSMiddleware with allow_origins=['*'] is overly permissive",
                                function=self._current_function(),
                            )
                        )
            for arg in node.args[1:]:
                if isinstance(arg, ast.Call):
                    middleware_func = arg.func
                    middleware_name = ""
                    if isinstance(middleware_func, ast.Name):
                        middleware_name = middleware_func.id
                    elif isinstance(middleware_func, ast.Attribute):
                        middleware_name = middleware_func.attr
                    if middleware_name == "CORSMiddleware":
                        for kw in arg.keywords:
                            if kw.arg == "allow_origins" and _is_wildcard_value(kw.value):
                                self.findings.append(
                                    CorsMisconfigFinding(
                                        path=self.path,
                                        lineno=node.lineno,
                                        pattern="fastapi_cors_wildcard",
                                        severity="high",
                                        message="FastAPI CORSMiddleware with allow_origins=['*'] is overly permissive",
                                        function=self._current_function(),
                                    )
                                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {
                "CORS_ORIGINS",
                "cors_allowed_origins",
                "CORS_ALLOWED_ORIGINS",
            }:
                if _is_wildcard_value(node.value):
                    self.findings.append(
                        CorsMisconfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="settings_cors_wildcard",
                            severity="high",
                            message=f"{target.id} set to wildcard — restrict to trusted origins",
                            function=self._current_function(),
                        )
                    )
            if isinstance(target, ast.Attribute) and target.attr in {"cors_allowed_origins", "CORS_ORIGINS"}:
                if _is_wildcard_value(node.value):
                    self.findings.append(
                        CorsMisconfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="django_cors_wildcard",
                            severity="high",
                            message="Django CORS allowed origins includes wildcard",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class CorsMisconfigAnalyzer:
    """Detect wildcard and overly permissive CORS configuration.

    Flags ``origins="*"`` in flask-cors, ``allow_origins=["*"]`` in FastAPI,
    and Django ``CORS_ALLOWED_ORIGINS`` wildcard settings.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CorsMisconfigFinding] = []
        self._stats: CorsMisconfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix not in {".py", ".yaml", ".yml", ".toml", ".env", ".ini"}

    def _scan_text_file(self, path: Path, rel: str) -> list[CorsMisconfigFinding]:
        findings: list[CorsMisconfigFinding] = []
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            if _WILDCARD_ORIGIN.search(line) or _WILDCARD_LIST.search(line):
                findings.append(
                    CorsMisconfigFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="config_cors_wildcard",
                        severity="high",
                        message="Configuration sets CORS origins to wildcard",
                    )
                )
        return findings

    def analyze(self) -> list[CorsMisconfigFinding]:
        """Analyze the project and return CORS misconfiguration findings."""
        if self._findings:
            return self._findings

        findings: list[CorsMisconfigFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue

            rel = str(path.relative_to(self.root))
            files_scanned += 1

            if path.suffix == ".py":
                try:
                    source = path.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=str(path))
                except (OSError, UnicodeDecodeError, SyntaxError):
                    continue
                visitor = _CorsVisitor(rel)
                visitor.visit(tree)
                file_findings = visitor.findings
            else:
                file_findings = self._scan_text_file(path, rel)

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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = CorsMisconfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CorsMisconfigStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CorsMisconfigFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CORS misconfigurations)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 30.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"CORS misconfigurations: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing CORS findings."""
        self.analyze()
        lines = [
            "CORS misconfiguration analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No CORS misconfiguration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
