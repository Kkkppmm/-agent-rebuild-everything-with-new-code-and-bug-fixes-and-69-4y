"""UnsafeDeserializationAnalyzer — detect unsafe pickle, yaml, and marshal usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|data|payload|body|content|blob|bytes|raw|"
    r"serialized|pickle|marshal|yaml|stream|file|upload|session|"
    r"param|query|cookie|token|cache|redis|queue|message)",
    re.IGNORECASE,
)

_UNSAFE_FUNCS = {
    ("pickle", "loads"): ("pickle_loads", "high", "pickle.loads on untrusted data enables arbitrary code execution"),
    ("pickle", "load"): ("pickle_load", "high", "pickle.load on untrusted data enables arbitrary code execution"),
    ("marshal", "loads"): ("marshal_loads", "high", "marshal.loads on untrusted data can execute attacker-controlled bytecode"),
    ("marshal", "load"): ("marshal_load", "high", "marshal.load on untrusted data can execute attacker-controlled bytecode"),
    ("shelve", "open"): ("shelve_open", "medium", "shelve uses pickle internally — do not open untrusted shelve files"),
    ("dill", "loads"): ("dill_loads", "high", "dill.loads on untrusted data enables arbitrary code execution"),
    ("dill", "load"): ("dill_load", "high", "dill.load on untrusted data enables arbitrary code execution"),
}


@dataclass
class UnsafeDeserializationFinding:
    """A potentially unsafe deserialization pattern."""

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
    """Aggregate unsafe-deserialization analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _looks_like_user_input(node.func)
    return False


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


def _module_and_method(node: ast.Call) -> tuple[str, str]:
    name = _call_name(node)
    parts = name.split(".")
    if len(parts) >= 2:
        return parts[0], parts[-1]
    if len(parts) == 1:
        return parts[0], parts[0]
    return "", ""


def _has_safe_yaml_loader(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
            loader = kw.value.attr
            if loader in {"SafeLoader", "CSafeLoader", "BaseLoader"}:
                return True
        if kw.arg == "Loader" and isinstance(kw.value, ast.Name):
            if kw.value.id in {"SafeLoader", "CSafeLoader", "BaseLoader"}:
                return True
    for arg in node.args[1:]:
        if isinstance(arg, ast.Attribute) and arg.attr in {"SafeLoader", "CSafeLoader", "BaseLoader"}:
            return True
        if isinstance(arg, ast.Name) and arg.id in {"SafeLoader", "CSafeLoader", "BaseLoader"}:
            return True
    return False


def _first_arg_is_user_input(node: ast.Call) -> bool:
    if not node.args:
        return True
    return _looks_like_user_input(node.args[0])


def _is_unsafe_deserialization(node: ast.Call) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) for risky deserialization calls."""
    module, method = _module_and_method(node)
    key = (module, method)

    if key in _UNSAFE_FUNCS:
        pattern, severity, message = _UNSAFE_FUNCS[key]
        if _first_arg_is_user_input(node) or not node.args:
            return pattern, severity, message
        return pattern, "medium", message

    if module == "yaml" and method == "load":
        if _has_safe_yaml_loader(node):
            return None
        return (
            "yaml_load_unsafe",
            "high",
            "yaml.load without SafeLoader — use yaml.safe_load or yaml.load(data, Loader=yaml.SafeLoader)",
        )

    if module == "yaml" and method == "unsafe_load":
        return (
            "yaml_unsafe_load",
            "high",
            "yaml.unsafe_load executes arbitrary Python objects — never use on untrusted input",
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
        result = _is_unsafe_deserialization(node)
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
    """Detect unsafe deserialization of untrusted data.

    Flags ``pickle.loads``, ``marshal.loads``, ``yaml.load`` without
  ``SafeLoader``, and similar patterns that can lead to remote code execution.
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
        """Analyze the project and return unsafe-deserialization findings."""
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

    def high_severity(self) -> list[UnsafeDeserializationFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no unsafe deserialization)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 30.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Unsafe deserialization: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing unsafe-deserialization findings."""
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
