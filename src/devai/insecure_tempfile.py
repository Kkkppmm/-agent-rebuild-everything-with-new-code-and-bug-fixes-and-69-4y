"""InsecureTempfileAnalyzer — detect insecure temporary file patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_INSECURE_CALLS = frozenset({"mktemp", "tempnam", "tmpnam"})
_LINE_PATTERNS = (
    re.compile(r"\bmktemp\s*\("),
    re.compile(r"\btempnam\s*\("),
    re.compile(r"\btmpnam\s*\("),
    re.compile(r"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False"),
    re.compile(r"0o777|0o666|mode\s*=\s*['\"]w\+?['\"]"),
)


@dataclass
class InsecureTempfileFinding:
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
class InsecureTempfileStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _InsecureTempfileVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTempfileFinding] = []
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
        if isinstance(func, ast.Attribute) and func.attr in _INSECURE_CALLS:
            self.findings.append(
                InsecureTempfileFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="insecure_temp_api",
                    severity="high",
                    message=f"Avoid {func.attr}() — use mkstemp() or NamedTemporaryFile instead",
                    function=self._current_function(),
                )
            )
        if isinstance(func, ast.Attribute) and func.attr == "NamedTemporaryFile":
            for kw in node.keywords:
                if kw.arg == "delete" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(
                        InsecureTempfileFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="persistent_tempfile",
                            severity="medium",
                            message="NamedTemporaryFile with delete=False may leave sensitive files on disk",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class InsecureTempfileAnalyzer:
    """Detect insecure temporary file creation patterns in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureTempfileFinding] = []
        self._stats: InsecureTempfileStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[InsecureTempfileFinding]:
        findings: list[InsecureTempfileFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            if "mktemp" in line or "tempnam" in line or "tmpnam" in line:
                for pattern in _LINE_PATTERNS[:3]:
                    if pattern.search(line):
                        findings.append(
                            InsecureTempfileFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="insecure_temp_api",
                                severity="high",
                                message="Insecure temporary file API may allow symlink attacks",
                            )
                        )
                        break
            if "NamedTemporaryFile" in line and "delete=False" in line.replace(" ", ""):
                findings.append(
                    InsecureTempfileFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="persistent_tempfile",
                        severity="medium",
                        message="NamedTemporaryFile with delete=False may leave sensitive files on disk",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureTempfileFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureTempfileFinding] = []
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
            visitor = _InsecureTempfileVisitor(rel)
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
        self._stats = InsecureTempfileStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureTempfileStats:
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
            f"Insecure tempfile risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure tempfile analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure tempfile patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
