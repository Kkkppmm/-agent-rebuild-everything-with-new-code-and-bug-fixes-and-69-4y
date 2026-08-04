"""FilePermissionAnalyzer — detect overly permissive file operations."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RISKY_CHMOD = frozenset({0o777, 0o666, 0o7777, 777, 666, 7777})
_PERMS_FUNCS = frozenset({"chmod", "chown", "umask"})


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


class _FilePermissionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[FilePermissionFinding] = []
        self._current_fn = "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _PERMS_FUNCS:
            if func.attr == "chmod" and node.args:
                mode = node.args[-1]
                if isinstance(mode, ast.Constant) and mode.value in _RISKY_CHMOD:
                    self.findings.append(
                        FilePermissionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="world_writable_chmod",
                            severity="high",
                            message=f"os.chmod with overly permissive mode {mode.value}",
                            function=self._current_fn,
                        )
                    )
            elif func.attr in {"chown", "umask"}:
                self.findings.append(
                    FilePermissionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=f"risky_{func.attr}",
                        severity="medium",
                        message=f"Direct {func.attr} call may expose permission issues",
                        function=self._current_fn,
                    )
                )
        if isinstance(func, ast.Name) and func.id == "open" and len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and mode_arg.value in {"w", "a", "x", "wb", "ab"}:
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        if kw.value.value in _RISKY_CHMOD:
                            self.findings.append(
                                FilePermissionFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="world_writable_open",
                                    severity="high",
                                    message="open() with world-writable file mode",
                                    function=self._current_fn,
                                )
                            )
        self.generic_visit(node)


class FilePermissionAnalyzer:
    """Detect chmod, chown, and open calls with overly permissive modes."""

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
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 10.0
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
            lines.append("No risky file permission patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
