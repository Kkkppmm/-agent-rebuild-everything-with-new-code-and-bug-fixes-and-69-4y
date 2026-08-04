"""FilePermissionAnalyzer — detect overly permissive file permission patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WORLD_WRITABLE = frozenset(
    {
        0o777,
        0o666,
        0o7777,
        511,
        438,
        4095,
    }
)
_PERMISSIVE_MODES = frozenset({"w", "a", "wb", "ab", "w+", "a+", "wb+", "ab+"})


@dataclass
class FilePermissionFinding:
    """An overly permissive file permission pattern."""

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


def _chmod_mode_value(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _chmod_mode_value(node.left)
        right = _chmod_mode_value(node.right)
        if left is not None and right is not None:
            return left | right
    return None


def _is_world_writable_mode(mode: int) -> bool:
    return mode in _WORLD_WRITABLE or (mode & 0o002) != 0 or (mode & 0o020) != 0


class _FilePermissionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect file permission risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[FilePermissionFinding] = []
        self._function_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        fn = self._function_stack[-1] if self._function_stack else ""
        self.findings.append(
            FilePermissionFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=fn,
            )
        )

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
        if isinstance(func, ast.Attribute) and func.attr == "chmod":
            if len(node.args) >= 2:
                mode = _chmod_mode_value(node.args[1])
                if mode is not None and _is_world_writable_mode(mode):
                    self._add(
                        node,
                        "chmod",
                        severity="high",
                        message=f"World-writable mode {mode} — restrict file permissions",
                    )
        if isinstance(func, ast.Name) and func.id == "chmod":
            if len(node.args) >= 2:
                mode = _chmod_mode_value(node.args[1])
                if mode is not None and _is_world_writable_mode(mode):
                    self._add(
                        node,
                        "os.chmod",
                        severity="high",
                        message=f"World-writable mode {mode} — restrict file permissions",
                    )
        if isinstance(func, ast.Attribute) and func.attr == "makedirs":
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode = _chmod_mode_value(kw.value)
                    if mode is not None and _is_world_writable_mode(mode):
                        self._add(
                            node,
                            "makedirs",
                            severity="high",
                            message=f"World-writable directory mode {mode}",
                        )
        if isinstance(func, ast.Name) and func.id == "open":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode_str = node.args[1].value
                if isinstance(mode_str, str) and mode_str in _PERMISSIVE_MODES:
                    self._add(
                        node,
                        "open",
                        severity="medium",
                        message=f"Open with mode '{mode_str}' — ensure files are not world-readable",
                    )
        self.generic_visit(node)


class FilePermissionAnalyzer:
    """Detect overly permissive file and directory permission patterns.

    Flags ``chmod`` / ``os.chmod`` with world-writable modes, permissive
    ``makedirs`` modes, and broad ``open()`` write modes.
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
        """Return aggregate file-permission statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[FilePermissionFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no permission issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"File permissions: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
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
            lines.append("No file permission issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
