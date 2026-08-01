"""UnsafeDeserializationAnalyzer — detect unsafe deserialization patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNSAFE_LOAD_FUNCS: dict[str, tuple[str, str, str]] = {
    "pickle.load": ("pickle_load", "critical", "pickle.load can execute arbitrary code — use JSON or signed formats"),
    "pickle.loads": ("pickle_loads", "critical", "pickle.loads can execute arbitrary code — use JSON or signed formats"),
    "cPickle.load": ("cpickle_load", "critical", "cPickle.load can execute arbitrary code"),
    "cPickle.loads": ("cpickle_loads", "critical", "cPickle.loads can execute arbitrary code"),
    "marshal.load": ("marshal_load", "high", "marshal.load is not safe for untrusted data"),
    "marshal.loads": ("marshal_loads", "high", "marshal.loads is not safe for untrusted data"),
    "shelve.open": ("shelve_open", "high", "shelve uses pickle internally — unsafe for untrusted data"),
    "dill.load": ("dill_load", "critical", "dill.load can execute arbitrary code"),
    "dill.loads": ("dill_loads", "critical", "dill.loads can execute arbitrary code"),
    "cloudpickle.load": ("cloudpickle_load", "critical", "cloudpickle.load can execute arbitrary code"),
    "cloudpickle.loads": ("cloudpickle_loads", "critical", "cloudpickle.loads can execute arbitrary code"),
}


@dataclass
class UnsafeDeserializationFinding:
    """An unsafe deserialization call."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class UnsafeDeserializationStats:
    """Aggregate unsafe deserialization statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _is_yaml_unsafe_load(node: ast.Call) -> tuple[str, str, str] | None:
    name = _call_name(node)
    if name not in {"yaml.load", "yaml.unsafe_load"}:
        return None
    loader = None
    for kw in node.keywords:
        if kw.arg == "Loader":
            loader = kw.value
            break
    if loader is None:
        return (
            "yaml_load_no_loader",
            "critical",
            "yaml.load without safe Loader — can execute arbitrary Python objects",
        )
    if isinstance(loader, ast.Attribute) and loader.attr == "Loader":
        return (
            "yaml_unsafe_loader",
            "critical",
            "yaml.load with unsafe Loader — use yaml.safe_load instead",
        )
    if isinstance(loader, ast.Name) and loader.id == "Loader":
        return (
            "yaml_unsafe_loader",
            "critical",
            "yaml.load with unsafe Loader — use yaml.safe_load instead",
        )
    return None


def _check_deserialization_call(node: ast.Call) -> tuple[str, str, str] | None:
    name = _call_name(node)
    if name in _UNSAFE_LOAD_FUNCS:
        return _UNSAFE_LOAD_FUNCS[name]
    return _is_yaml_unsafe_load(node)


class _UnsafeDeserializationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe deserialization calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[UnsafeDeserializationFinding] = []
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
        result = _check_deserialization_call(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                UnsafeDeserializationFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                    call=_call_name(node),
                )
            )
        self.generic_visit(node)


class UnsafeDeserializationAnalyzer:
    """Detect unsafe deserialization in Python projects.

    Flags pickle, marshal, dill, shelve, and unsafe yaml.load usage
    that can lead to remote code execution.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[UnsafeDeserializationFinding] = []
        self._stats: UnsafeDeserializationStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[UnsafeDeserializationFinding]:
        """Analyze the project and return unsafe deserialization findings."""
        if self._findings:
            return self._findings

        findings: list[UnsafeDeserializationFinding] = []
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
            visitor = _UnsafeDeserializationVisitor(rel)
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

        self._stats = UnsafeDeserializationStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> UnsafeDeserializationStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def critical(self) -> list[UnsafeDeserializationFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no unsafe deserialization)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = critical * 30.0 + high * 15.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Unsafe deserialization: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing unsafe deserialization findings."""
        self.analyze()
        lines = [
            "Unsafe deserialization analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No unsafe deserialization patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
