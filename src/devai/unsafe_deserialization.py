"""UnsafeDeserializationAnalyzer — detect unsafe object deserialization patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNSAFE_LOAD_ATTRS = frozenset({"loads", "load", "decode", "unpickle"})
_UNSAFE_MODULES = frozenset({"pickle", "cPickle", "_pickle", "marshal", "dill", "jsonpickle", "shelve"})
_YAML_LOAD_ATTRS = frozenset({"load", "load_all", "unsafe_load", "unsafe_load_all"})


@dataclass
class UnsafeDeserializationFinding:
    """A potentially unsafe deserialization call."""

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
class UnsafeDeserializationStats:
    """Aggregate unsafe deserialization statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _module_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _is_yaml_safe_load(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "safe_load":
        return True
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader = kw.value
            if isinstance(loader, ast.Attribute) and loader.attr in {"SafeLoader", "CSafeLoader"}:
                return True
            if isinstance(loader, ast.Name) and loader.id in {"SafeLoader", "CSafeLoader"}:
                return True
    return False


def _classify_deserialization_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    attr = func.attr
    module = _module_name(func.value)
    if not module:
        return None

    base_module = module.split(".")[0]

    if base_module == "yaml" and attr in _YAML_LOAD_ATTRS:
        if _is_yaml_safe_load(call):
            return None
        return (
            "yaml_unsafe_load",
            "high",
            "yaml.load() without SafeLoader can execute arbitrary code — use yaml.safe_load()",
        )

    if base_module in _UNSAFE_MODULES and attr in _UNSAFE_LOAD_ATTRS:
        severity = "critical" if base_module in {"pickle", "cPickle", "_pickle", "dill"} else "high"
        return (
            f"{base_module}_{attr}",
            severity,
            f"{module}.{attr}() deserializes untrusted data — never use on user input",
        )

    if base_module == "shelve" and attr == "open":
        return (
            "shelve_open",
            "medium",
            "shelve.open() uses pickle internally — do not open untrusted shelf files",
        )

    return None


class _UnsafeDeserializationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe deserialization risks."""

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
        result = _classify_deserialization_call(node)
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
                )
            )
        self.generic_visit(node)


class UnsafeDeserializationAnalyzer:
    """Detect unsafe deserialization of untrusted data.

    Flags pickle.loads, yaml.load without SafeLoader, marshal.loads,
    dill.loads, and similar patterns that can lead to remote code execution.
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
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 30.0 + high * 20.0 + medium * 8.0
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
