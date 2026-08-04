"""UnsafeDeserializationAnalyzer — detect unsafe deserialization of untrusted data."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|data|payload|body|content|blob|bytes|raw|"
    r"cookie|session|token|param|query|file|upload|message|packet|"
    r"response|recv|read|load|deserialize|decode|parse)",
    re.IGNORECASE,
)

_UNSAFE_LOAD_FUNCS: dict[str, tuple[str, str, str]] = {
    "pickle.loads": ("pickle_loads", "critical", "pickle.loads on untrusted data enables RCE"),
    "pickle.load": ("pickle_load", "critical", "pickle.load on untrusted data enables RCE"),
    "_pickle.loads": ("pickle_loads", "critical", "pickle.loads on untrusted data enables RCE"),
    "cPickle.loads": ("pickle_loads", "critical", "cPickle.loads on untrusted data enables RCE"),
    "marshal.loads": ("marshal_loads", "high", "marshal.loads on untrusted data is unsafe"),
    "shelve.open": ("shelve_open", "high", "shelve may deserialize pickle data from untrusted sources"),
    "dill.loads": ("dill_loads", "critical", "dill.loads on untrusted data enables RCE"),
    "jsonpickle.decode": ("jsonpickle_decode", "critical", "jsonpickle.decode can execute arbitrary code"),
    "yaml.load": ("yaml_load", "high", "yaml.load without SafeLoader can execute arbitrary code"),
    "yaml.unsafe_load": ("yaml_unsafe_load", "critical", "yaml.unsafe_load executes arbitrary Python objects"),
    "yaml.load_all": ("yaml_load_all", "high", "yaml.load_all without SafeLoader can execute arbitrary code"),
}


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


def _first_data_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in {"data", "s", "stream", "filename", "buffer"}:
            return kw.value
    return None


def _uses_safe_loader(node: ast.Call) -> bool:
    for arg in node.args[1:]:
        if isinstance(arg, ast.Attribute) and arg.attr == "SafeLoader":
            return True
        if isinstance(arg, ast.Name) and arg.id == "SafeLoader":
            return True
    for kw in node.keywords:
        if kw.arg == "Loader":
            val = kw.value
            if isinstance(val, ast.Attribute) and val.attr == "SafeLoader":
                return True
            if isinstance(val, ast.Name) and val.id == "SafeLoader":
                return True
    return False


def _is_unsafe_deserialization(node: ast.Call) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) for unsafe deserialization calls."""
    name = _call_name(node)
    data_arg = _first_data_arg(node)

    if name in {"yaml.load", "yaml.load_all"} and _uses_safe_loader(node):
        return None

    if name in _UNSAFE_LOAD_FUNCS:
        pattern, severity, message = _UNSAFE_LOAD_FUNCS[name]
        if data_arg is None or _looks_like_user_input(data_arg):
            return pattern, severity, message

    parts = name.split(".")
    method = parts[-1] if parts else name
    if method in {"loads", "load", "decode"} and _looks_like_user_input(_first_data_arg(node) or node):
        module = parts[0] if len(parts) > 1 else ""
        if module in {"pickle", "_pickle", "cPickle", "dill", "marshal", "jsonpickle"}:
            return (
                f"{module}_{method}",
                "critical",
                f"{name} on untrusted data enables arbitrary code execution",
            )

    return None


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
    """Detect unsafe deserialization of untrusted data in Python projects.

    Flags pickle, marshal, dill, jsonpickle, yaml.load (without SafeLoader),
    and shelve usage with user-controlled input.
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
        penalty = critical * 30.0 + high * 20.0
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
