"""ClickjackingAnalyzer — detect missing clickjacking protections."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_FRAME_PROTECTION_HEADERS = frozenset(
    {"X-Frame-Options", "x-frame-options", "Content-Security-Policy", "content-security-policy"}
)
_ROUTE_DECORATORS = frozenset({"route", "get", "post", "app", "api_route"})


@dataclass
class ClickjackingFinding:
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
class ClickjackingStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


class _ClickjackingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ClickjackingFinding] = []
        self._has_frame_protection = False
        self._has_route_handler = False

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                key = target.slice
                if isinstance(key, ast.Constant) and key.value in _FRAME_PROTECTION_HEADERS:
                    self._has_frame_protection = True
            if isinstance(target, ast.Attribute) and target.attr in {"X_FRAME_OPTIONS", "CSP"}:
                self._has_frame_protection = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"set_header", "add_header"}:
            if node.args and isinstance(node.args[0], ast.Constant):
                if node.args[0].value in _FRAME_PROTECTION_HEADERS:
                    self._has_frame_protection = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if any(_decorator_name(d) in _ROUTE_DECORATORS for d in node.decorator_list):
            self._has_route_handler = True
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if any(_decorator_name(d) in _ROUTE_DECORATORS for d in node.decorator_list):
            self._has_route_handler = True
        self.generic_visit(node)

    def finalize(self) -> None:
        if self._has_route_handler and not self._has_frame_protection:
            self.findings.append(
                ClickjackingFinding(
                    path=self.path,
                    lineno=1,
                    pattern="missing_frame_protection",
                    severity="medium",
                    message="Web handlers present without X-Frame-Options or CSP frame-ancestors",
                    function="<module>",
                )
            )


class ClickjackingAnalyzer:
    """Detect web apps missing X-Frame-Options or CSP frame-ancestors headers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ClickjackingFinding] = []
        self._stats: ClickjackingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[ClickjackingFinding]:
        if self._findings:
            return self._findings

        findings: list[ClickjackingFinding] = []
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
            visitor = _ClickjackingVisitor(rel)
            visitor.visit(tree)
            visitor.finalize()
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
        self._stats = ClickjackingStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ClickjackingStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Clickjacking risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Clickjacking analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No clickjacking risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
