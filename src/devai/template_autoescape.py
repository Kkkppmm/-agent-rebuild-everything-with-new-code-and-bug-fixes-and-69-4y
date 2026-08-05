"""TemplateAutoescapeAnalyzer — detect Jinja2 environments without autoescape."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class TemplateAutoescapeFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class TemplateAutoescapeStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_environment_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Name) and func.id == "Environment":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "Environment":
        if isinstance(func.value, ast.Name) and func.value.id in {"jinja2", "jinja"}:
            return True
    return False


def _autoescape_kwarg(call: ast.Call) -> ast.keyword | None:
    for kw in call.keywords:
        if kw.arg == "autoescape":
            return kw
    return None


def _is_safe_autoescape(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant) and value.value is True:
        return True
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Name) and func.id == "select_autoescape":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "select_autoescape":
            return True
    return False


def _classify_environment_call(call: ast.Call) -> tuple[str, str, str] | None:
    if not _is_environment_call(call.func):
        return None

    kw = _autoescape_kwarg(call)
    if kw is None:
        return (
            "missing_template_autoescape",
            "high",
            "Jinja2 Environment() without autoescape enables XSS — use autoescape=True or select_autoescape()",
        )

    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
        return (
            "disabled_template_autoescape",
            "high",
            "Jinja2 Environment(autoescape=False) disables XSS protection",
        )

    if _is_safe_autoescape(kw.value):
        return None

    return (
        "unsafe_template_autoescape",
        "medium",
        "Jinja2 Environment autoescape is not explicitly enabled — use autoescape=True or select_autoescape()",
    )


class _TemplateAutoescapeVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TemplateAutoescapeFinding] = []
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
        rule = _classify_environment_call(node)
        if rule:
            pattern, severity, message = rule
            self.findings.append(
                TemplateAutoescapeFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class TemplateAutoescapeAnalyzer:
    """Detect Jinja2 template environments missing or disabling autoescape."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TemplateAutoescapeFinding] = []
        self._stats: TemplateAutoescapeStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[TemplateAutoescapeFinding]:
        if self._findings:
            return self._findings

        findings: list[TemplateAutoescapeFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _TemplateAutoescapeVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = TemplateAutoescapeStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TemplateAutoescapeStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 12.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Template autoescape: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Template autoescape analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Jinja2 Environment configurations found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
