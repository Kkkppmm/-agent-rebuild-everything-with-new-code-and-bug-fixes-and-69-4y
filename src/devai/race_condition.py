"""RaceConditionAnalyzer — detect time-of-check/time-of-use and concurrency risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_TOCTOU_PATTERNS = (
    re.compile(r"os\.path\.exists\s*\("),
    re.compile(r"pathlib\.Path\s*\([^)]+\)\.exists\s*\("),
    re.compile(r"if\s+not\s+os\.path\.exists"),
)
_WRITE_AFTER_CHECK = re.compile(r"(open|write|mkdir|makedirs|unlink|remove)\s*\(")


@dataclass
class RaceConditionFinding:
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
class RaceConditionStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _RaceConditionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[RaceConditionFinding] = []
        self._function_stack: list[str] = []
        self._has_threading = False
        self._has_lock = False
        self._global_names: set[str] = set()
        self._mutated_globals: set[str] = set()

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "threading" or alias.name == "multiprocessing":
                self._has_threading = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"threading", "multiprocessing", "concurrent.futures"}:
            self._has_threading = True
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self._global_names.update(node.names)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        saved_globals = set(self._global_names)
        saved_mutated = set(self._mutated_globals)
        self.generic_visit(node)
        self._function_stack.pop()
        self._global_names = saved_globals
        self._mutated_globals = saved_mutated

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        saved_globals = set(self._global_names)
        saved_mutated = set(self._mutated_globals)
        self.generic_visit(node)
        self._function_stack.pop()
        self._global_names = saved_globals
        self._mutated_globals = saved_mutated

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_global_mutation(target, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_global_mutation(node.target, node.lineno)
        self.generic_visit(node)

    def _check_global_mutation(self, target: ast.AST, lineno: int) -> None:
        if isinstance(target, ast.Name) and target.id in self._global_names:
            self._mutated_globals.add(target.id)
            if self._has_threading and not self._has_lock:
                self.findings.append(
                    RaceConditionFinding(
                        path=self.path,
                        lineno=lineno,
                        pattern="global_mutation",
                        severity="medium",
                        message="Global variable mutated without visible lock in threaded code",
                        function=self._current_function(),
                    )
                )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"Lock", "RLock", "Semaphore"}:
                self._has_lock = True
            if func.attr == "exists" and isinstance(func.value, ast.Attribute):
                if func.value.attr == "path" or (
                    isinstance(func.value.value, ast.Name) and func.value.value.id == "os"
                ):
                    self._check_toctou_after(node.lineno)
        if isinstance(func, ast.Name) and func.id in {"open", "unlink", "remove"}:
            self._check_toctou_before(node.lineno)
        self.generic_visit(node)

    def _check_toctou_after(self, check_lineno: int) -> None:
        if self._has_lock:
            return
        self.findings.append(
            RaceConditionFinding(
                path=self.path,
                lineno=check_lineno,
                pattern="toctou_file_check",
                severity="medium",
                message="File existence check without lock may race with concurrent writers",
                function=self._current_function(),
            )
        )

    def _check_toctou_before(self, write_lineno: int) -> None:
        pass  # handled via line patterns for check-then-write sequences


class RaceConditionAnalyzer:
    """Detect race conditions, TOCTOU patterns, and unsafe global mutations."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[RaceConditionFinding] = []
        self._stats: RaceConditionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[RaceConditionFinding]:
        findings: list[RaceConditionFinding] = []
        lines = source.splitlines()
        saw_exists_check = False
        check_lineno = 0
        for lineno, line in enumerate(lines, start=1):
            if any(p.search(line) for p in _TOCTOU_PATTERNS):
                saw_exists_check = True
                check_lineno = lineno
            elif saw_exists_check and _WRITE_AFTER_CHECK.search(line):
                findings.append(
                    RaceConditionFinding(
                        path=rel,
                        lineno=check_lineno,
                        pattern="toctou_check_then_write",
                        severity="high",
                        message="Check-then-write file pattern vulnerable to race conditions",
                    )
                )
                saw_exists_check = False
            elif line.strip() and not line.strip().startswith("#") and saw_exists_check:
                if lineno - check_lineno > 3:
                    saw_exists_check = False
        return findings

    def analyze(self) -> list[RaceConditionFinding]:
        if self._findings:
            return self._findings

        findings: list[RaceConditionFinding] = []
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
            visitor = _RaceConditionVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            combined = visitor.findings + line_findings
            if combined:
                files_with_findings.add(rel)
            findings.extend(combined)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = RaceConditionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> RaceConditionStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Race condition risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Race condition analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No race condition risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
