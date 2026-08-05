"""DynamicImportAnalyzer — detect dynamic module imports that may load arbitrary code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_IMPORT_MODULE = re.compile(r"\bimport_module\s*\(")
_DUNDER_IMPORT = re.compile(r"\b__import__\s*\(")


@dataclass
class DynamicImportFinding:
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
class DynamicImportStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_literal_string(node: ast.expr | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(part, ast.Constant) for part in node.values)
    return False


class _DynamicImportVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DynamicImportFinding] = []
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

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            DynamicImportFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 1),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Name) and func.id == "__import__":
            module_arg = node.args[0] if node.args else None
            if not _is_literal_string(module_arg):
                self._add(
                    node,
                    "dunder_import",
                    "high",
                    "__import__() with a dynamic module name can load arbitrary code",
                )

        if isinstance(func, ast.Attribute):
            if func.attr == "import_module":
                module_arg = node.args[0] if node.args else None
                if not _is_literal_string(module_arg):
                    self._add(
                        node,
                        "importlib_import_module",
                        "high",
                        "importlib.import_module() with a dynamic name can load arbitrary modules",
                    )
            elif func.attr == "spec_from_file_location":
                path_arg = node.args[1] if len(node.args) > 1 else node.args[0] if node.args else None
                if not _is_literal_string(path_arg):
                    self._add(
                        node,
                        "spec_from_file_location",
                        "high",
                        "Loading modules from dynamic file paths can execute arbitrary code",
                    )
            elif func.attr == "load_module" and isinstance(func.value, ast.Attribute):
                if func.value.attr == "imp":
                    self._add(
                        node,
                        "deprecated_imp",
                        "medium",
                        "imp.load_module() is deprecated and unsafe with untrusted names",
                    )

        self.generic_visit(node)


class DynamicImportAnalyzer:
    """Detect dynamic imports that may load arbitrary Python modules."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DynamicImportFinding] = []
        self._stats: DynamicImportStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[DynamicImportFinding]:
        findings: list[DynamicImportFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _DUNDER_IMPORT.search(line) and not re.search(r"""__import__\s*\(\s*['"]""", line):
                findings.append(
                    DynamicImportFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="dunder_import",
                        severity="high",
                        message="__import__() with a dynamic module name can load arbitrary code",
                    )
                )
            if _IMPORT_MODULE.search(line) and not re.search(
                r"""import_module\s*\(\s*['"]""", line
            ):
                findings.append(
                    DynamicImportFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="importlib_import_module",
                        severity="high",
                        message="importlib.import_module() with a dynamic name can load arbitrary modules",
                    )
                )
        return findings

    def analyze(self) -> list[DynamicImportFinding]:
        if self._findings:
            return self._findings

        findings: list[DynamicImportFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()
        seen: set[tuple[str, int, str]] = set()

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
            visitor = _DynamicImportVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            combined = visitor.findings + line_findings
            deduped: list[DynamicImportFinding] = []
            for finding in combined:
                key = (finding.path, finding.lineno, finding.pattern)
                if key not in seen:
                    seen.add(key)
                    deduped.append(finding)
            if deduped:
                files_with_findings.add(rel)
            findings.extend(deduped)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = DynamicImportStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DynamicImportStats:
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
            f"Dynamic import risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Dynamic import analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unsafe dynamic import patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
