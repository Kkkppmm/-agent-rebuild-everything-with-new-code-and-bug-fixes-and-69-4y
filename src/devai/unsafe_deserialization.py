"""UnsafeDeserializationAnalyzer — detect unsafe deserialization of untrusted data."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|data|payload|body|content|blob|bytes|raw|"
    r"stream|file|upload|message|packet|response|recv|read)",
    re.IGNORECASE,
)

_UNSAFE_LOADERS = frozenset({
    "pickle",
    "marshal",
    "dill",
    "jsonpickle",
    "shelve",
    "cpickle",
})

_UNSAFE_LOAD_FUNCS = frozenset({"loads", "load", "Unpickler", "load_session"})


@dataclass
class UnsafeDeserializationFinding:
    """A potentially unsafe deserialization call."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        call = f" ({self.call})" if self.call else ""
        return (
            f"{self.path}:{self.lineno}{call} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class UnsafeDeserializationStats:
    """Aggregate unsafe-deserialization statistics."""

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


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _module_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return None


def _is_unsafe_yaml_load(node: ast.Call) -> bool:
    name = _call_name(node)
    if name != "load":
        return False
    module = _module_name(node)
    if module != "yaml":
        return False
    for kw in node.keywords:
        if kw.arg == "Loader":
            if isinstance(kw.value, ast.Attribute):
                loader = kw.value.attr
                if loader in {"SafeLoader", "CSafeLoader", "BaseLoader"}:
                    return False
            if isinstance(kw.value, ast.Name) and kw.value.id in {"SafeLoader", "CSafeLoader"}:
                return False
    return True


class _UnsafeDeserializationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe deserialization risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[UnsafeDeserializationFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            UnsafeDeserializationFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                call=call,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        module = _module_name(node)

        if _is_unsafe_yaml_load(node):
            arg_risky = any(_looks_like_user_input(arg) for arg in node.args)
            severity = "high" if arg_risky else "medium"
            self._add(
                node,
                "unsafe_yaml_load",
                severity=severity,
                message="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                call="yaml.load",
            )
        elif name in _UNSAFE_LOAD_FUNCS and module in _UNSAFE_LOADERS:
            arg_risky = any(_looks_like_user_input(arg) for arg in node.args)
            severity = "high" if arg_risky else "high"
            self._add(
                node,
                f"unsafe_{module}_deserialize",
                severity=severity,
                message=f"{module}.{name}() can execute arbitrary code on untrusted data",
                call=f"{module}.{name}",
            )
        elif name in _UNSAFE_LOAD_FUNCS and name == "loads":
            if isinstance(node.func, ast.Attribute):
                base = node.func.value
                if isinstance(base, ast.Name) and base.id in _UNSAFE_LOADERS:
                    arg_risky = any(_looks_like_user_input(arg) for arg in node.args)
                    severity = "high" if arg_risky else "high"
                    self._add(
                        node,
                        f"unsafe_{base.id}_loads",
                        severity=severity,
                        message=f"{base.id}.loads() can execute arbitrary code on untrusted data",
                        call=f"{base.id}.loads",
                    )
        elif name == "loads" and isinstance(node.func, ast.Name) and node.func.id == "pickle":
            arg_risky = any(_looks_like_user_input(arg) for arg in node.args)
            self._add(
                node,
                "unsafe_pickle_loads",
                severity="high",
                message="pickle.loads() can execute arbitrary code on untrusted data",
                call="pickle.loads",
            )

        self.generic_visit(node)


class UnsafeDeserializationAnalyzer:
    """Detect unsafe deserialization of potentially untrusted data.

    Flags ``pickle.loads``, ``marshal.loads``, unsafe ``yaml.load``,
    and similar patterns that can lead to remote code execution.
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        """Return aggregate unsafe-deserialization statistics."""
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
        penalty = high * 30.0 + medium * 15.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

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
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing unsafe-deserialization findings."""
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
