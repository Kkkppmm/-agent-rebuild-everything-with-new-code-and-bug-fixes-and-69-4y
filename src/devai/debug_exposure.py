"""DebugExposureAnalyzer — detect debug mode and verbose error exposure in production code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_DEBUG_ASSIGNMENTS = frozenset({"DEBUG", "debug", "FLASK_DEBUG", "DJANGO_DEBUG"})
_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "config.py",
        "production.py",
        "prod.py",
        "app.py",
        "main.py",
        "wsgi.py",
    }
)
_TRACEBACK_PATTERNS = (
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True"),
)


@dataclass
class DebugExposureFinding:
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
class DebugExposureStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _DebugExposureVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[DebugExposureFinding] = []
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _DEBUG_ASSIGNMENTS:
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    severity = "high" if self.filename in _PROD_FILENAMES else "medium"
                    self.findings.append(
                        DebugExposureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="debug_enabled",
                            severity=severity,
                            message=f"{target.id} = True may expose stack traces in production",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        DebugExposureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="flask_debug_run",
                            severity="high",
                            message="app.run(debug=True) exposes Werkzeug debugger — disable in production",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class DebugExposureAnalyzer:
    """Detect debug mode flags and verbose error exposure in application code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DebugExposureFinding] = []
        self._stats: DebugExposureStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[DebugExposureFinding]:
        findings: list[DebugExposureFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _TRACEBACK_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        DebugExposureFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="traceback_exposure",
                            severity="medium",
                            message="Traceback may be exposed to users — log internally instead",
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[DebugExposureFinding]:
        if self._findings:
            return self._findings

        findings: list[DebugExposureFinding] = []
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
            visitor = _DebugExposureVisitor(rel, path.name)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            all_findings = visitor.findings + line_findings
            if all_findings:
                files_with_findings.add(rel)
            findings.extend(all_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = DebugExposureStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DebugExposureStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Debug exposure risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Debug exposure analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No debug exposure patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
