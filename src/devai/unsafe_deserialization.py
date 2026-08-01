"""UnsafeDeserializationAnalyzer — detect unsafe pickle, yaml, and marshal usage."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNSAFE_LOADS: dict[str, tuple[str, str, str]] = {
    "pickle.loads": ("pickle_loads", "critical", "pickle.loads executes arbitrary code — use JSON or signed tokens"),
    "pickle.load": ("pickle_load", "critical", "pickle.load executes arbitrary code — never load untrusted data"),
    "marshal.loads": ("marshal_loads", "high", "marshal.loads can execute attacker-controlled bytecode"),
    "marshal.load": ("marshal_load", "high", "marshal.load can execute attacker-controlled bytecode"),
    "shelve.open": ("shelve_open", "high", "shelve uses pickle internally — unsafe with untrusted data"),
    "dill.loads": ("dill_loads", "critical", "dill.loads executes arbitrary code — use JSON for untrusted input"),
    "dill.load": ("dill_load", "critical", "dill.load executes arbitrary code — use JSON for untrusted input"),
}

_YAML_LOAD_ATTRS = frozenset({"load", "load_all", "unsafe_load", "unsafe_load_all"})
_YAML_SAFE_LOAD_ATTRS = frozenset({"safe_load", "safe_load_all"})


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
    """Aggregate unsafe deserialization analysis statistics."""

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


def _is_unsafe_yaml_load(node: ast.Call) -> tuple[str, str, str] | None:
    name = _call_name(node)
    parts = name.split(".")
    module = parts[0] if parts else ""
    method = parts[-1] if parts else ""

    if module == "yaml" and method in _YAML_LOAD_ATTRS:
        has_loader = any(kw.arg == "Loader" for kw in node.keywords)
        if not has_loader:
            return (
                "yaml_load_no_loader",
                "critical",
                "yaml.load without SafeLoader can execute arbitrary Python objects",
            )
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader_name = _call_name(kw.value) if isinstance(kw.value, ast.Call) else ""
                if isinstance(kw.value, ast.Attribute):
                    loader_name = kw.value.attr
                if loader_name and "Unsafe" in loader_name:
                    return (
                        "yaml_unsafe_loader",
                        "critical",
                        "yaml.load with UnsafeLoader allows arbitrary code execution",
                    )
    return None


class _UnsafeDeserializationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe deserialization calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[UnsafeDeserializationFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.Call,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)

        if name in _UNSAFE_LOADS:
            pattern, severity, message = _UNSAFE_LOADS[name]
            self._add(node, pattern, severity, message)
        else:
            yaml_result = _is_unsafe_yaml_load(node)
            if yaml_result:
                pattern, severity, message = yaml_result
                self._add(node, pattern, severity, message)

        self.generic_visit(node)


class UnsafeDeserializationAnalyzer:
    """Detect unsafe deserialization patterns in Python projects.

    Flags pickle.loads, yaml.load without SafeLoader, marshal.loads,
    and other deserialization calls that can execute arbitrary code.
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

    def critical_findings(self) -> list[UnsafeDeserializationFinding]:
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
        lines = ["Unsafe deserialization analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unsafe deserialization patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
