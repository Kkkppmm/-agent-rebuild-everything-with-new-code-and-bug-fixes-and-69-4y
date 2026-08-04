"""FilePermissionAnalyzer — detect overly permissive file permission changes."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WORLD_WRITABLE_MODES = frozenset({0o666, 0o777, 0o766, 0o776, 0o667, 0o677})
_WORLD_WRITABLE_DECIMAL = frozenset({438, 511, 502, 510, 439, 503})  # octal equivalents
_CHMOD_ATTRS = frozenset({"chmod"})
_CHMOD_MODULES = frozenset({"os", "pathlib", "Path"})


@dataclass
class FilePermissionFinding:
    """An overly permissive chmod or file permission change."""

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
class FilePermissionStats:
    """Aggregate file-permission analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _mode_value(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _is_world_writable(mode: int) -> bool:
    if mode in _WORLD_WRITABLE_MODES or mode in _WORLD_WRITABLE_DECIMAL:
        return True
    # Check octal permission bits: world-writable (other write bit set)
    if mode <= 0o7777 and (mode & 0o002):
        return True
    return False


def _is_chmod_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _CHMOD_ATTRS:
        return True
    if isinstance(func, ast.Name) and func.id == "chmod":
        return True
    return False


def _classify_chmod(node: ast.Call) -> tuple[str, str, str] | None:
    if not _is_chmod_call(node):
        return None
    mode_node: ast.AST | None = None
    if len(node.args) >= 2:
        mode_node = node.args[1]
    elif len(node.args) == 1:
        mode_node = node.args[0]
    if mode_node is None:
        return None
    mode = _mode_value(mode_node)
    if mode is None:
        return None
    if not _is_world_writable(mode):
        return None
    return (
        "world_writable_chmod",
        "high",
        f"chmod with mode {oct(mode) if mode <= 0o7777 else mode} grants world-writable permissions",
    )


class _FilePermissionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect permissive chmod patterns."""

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
        result = _classify_chmod(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                FilePermissionFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class FilePermissionAnalyzer:
    """Detect overly permissive file permission changes.

    Flags os.chmod() and Path.chmod() calls that set world-writable modes
    (e.g. 0o777, 0o666) which can expose sensitive files to other users.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[FilePermissionFinding] = []
        self._stats: FilePermissionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[FilePermissionFinding]:
        """Analyze the project and return file-permission findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no permissive chmod calls)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 20.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"File permission risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing file-permission findings."""
        self.analyze()
        lines = [
            "File permission analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No overly permissive chmod patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
