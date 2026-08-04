"""InsecureTempfileAnalyzer — detect predictable or unsafe temporary file usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_LINE_PATTERNS = (
    (re.compile(r"\btempfile\.mktemp\s*\("), "mktemp", "high", "tempfile.mktemp() is race-prone — use NamedTemporaryFile or mkstemp"),
    (re.compile(r"\bos\.mktemp\s*\("), "os_mktemp", "high", "os.mktemp() is race-prone — use tempfile.NamedTemporaryFile or mkstemp"),
    (re.compile(r"/tmp/[^'\"]*\{"), "hardcoded_tmp_format", "medium", "Predictable /tmp path with interpolation — use tempfile module"),
    (re.compile(r"['\"]/tmp/[^'\"]*['\"]\s*\+"), "hardcoded_tmp_concat", "medium", "Hardcoded /tmp path concatenation — use tempfile module"),
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
        if isinstance(func, ast.Attribute) and func.attr == "mktemp":
            mod = func.value
            if isinstance(mod, ast.Name) and mod.id in {"tempfile", "os"}:
                pattern = "mktemp" if mod.id == "tempfile" else "os_mktemp"
                self.findings.append(
                    InsecureTempfileFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity="high",
                        message=f"{mod.id}.mktemp() is race-prone — use NamedTemporaryFile or mkstemp",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class InsecureTempfileAnalyzer:
    """Detect mktemp, predictable /tmp paths, and other unsafe temp file patterns."""

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

            for lineno, line in enumerate(source.splitlines(), start=1):
                for pattern_re, pattern, severity, message in _LINE_PATTERNS:
                    if pattern_re.search(line):
                        if not any(f.lineno == lineno and f.pattern == pattern for f in visitor.findings):
                            visitor.findings.append(
                                InsecureTempfileFinding(
                                    path=rel,
                                    lineno=lineno,
                                    pattern=pattern,
                                    severity=severity,
                                    message=message,
                                )
                            )

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
        penalty = high * 20.0 + medium * 10.0
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
