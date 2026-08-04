"""FilePermissionAnalyzer — detect insecure file permission settings."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WORLD_WRITABLE = frozenset({0o777, 0o666, 0o776, 0o767, 0o757, 0o755, 0o775})
_LINE_PATTERNS = (
    re.compile(r"os\.chmod\s*\([^)]*,\s*0o?777"),
    re.compile(r"os\.chmod\s*\([^)]*,\s*0o?666"),
    re.compile(r"mode\s*=\s*0o?777"),
    re.compile(r"mode\s*=\s*0o?666"),
    re.compile(r"open\s*\([^)]*mode\s*=\s*['\"]w\+?['\"]"),
)


@dataclass
class FilePermissionFinding:
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
class FilePermissionStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _octal_mode(value: int) -> bool:
    return value in _WORLD_WRITABLE or (value & 0o002) != 0


class _FilePermissionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[FilePermissionFinding] = []
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
        if isinstance(func, ast.Attribute):
            if func.attr == "chmod" and len(node.args) >= 2:
                mode = node.args[1]
                if isinstance(mode, ast.Constant) and isinstance(mode.value, int):
                    if _octal_mode(mode.value):
                        self.findings.append(
                            FilePermissionFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="chmod_world_writable",
                                severity="high",
                                message=f"os.chmod with mode {oct(mode.value)} grants world-writable permissions",
                                function=self._current_function(),
                            )
                        )
            if func.attr == "makedirs":
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, int) and _octal_mode(kw.value.value):
                            self.findings.append(
                                FilePermissionFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="makedirs_world_writable",
                                    severity="high",
                                    message=f"os.makedirs with mode {oct(kw.value.value)} grants world-writable permissions",
                                    function=self._current_function(),
                                )
                            )
        if isinstance(func, ast.Name) and func.id == "chmod" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and _octal_mode(mode.value):
                self.findings.append(
                    FilePermissionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="chmod_world_writable",
                        severity="high",
                        message=f"chmod with mode {oct(mode.value)} grants world-writable permissions",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class FilePermissionAnalyzer:
    """Detect insecure file permission settings in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[FilePermissionFinding] = []
        self._stats: FilePermissionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, lines: list[str]) -> list[FilePermissionFinding]:
        findings: list[FilePermissionFinding] = []
        for lineno, line in enumerate(lines, start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        FilePermissionFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="line_insecure_permissions",
                            severity="high",
                            message="Insecure file permissions detected",
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[FilePermissionFinding]:
        if self._findings:
            return self._findings

        findings: list[FilePermissionFinding] = []
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
            visitor = _FilePermissionVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source.splitlines())
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
        self._stats = FilePermissionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> FilePermissionStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 15.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"File permission risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["File permission analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure file permission patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
