"""DangerousCallsAnalyzer — detect risky Python calls and anti-patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_MUTABLE_DEFAULT_TYPES = (ast.List, ast.Dict, ast.Set)

_DANGEROUS_CALLS: dict[str, tuple[str, str, str]] = {
    "eval": ("code_injection", "high", "eval() executes arbitrary code — avoid or sandbox strictly"),
    "exec": ("code_injection", "high", "exec() executes arbitrary code — avoid or sandbox strictly"),
    "compile": ("code_injection", "medium", "compile() can build executable code from strings"),
    "system": ("shell_injection", "high", "os.system() spawns a shell — use subprocess with a list"),
    "popen": ("shell_injection", "medium", "os.popen() spawns a shell process"),
    "loads": ("deserialization", "high", "pickle/marshal.loads() can execute arbitrary code on untrusted data"),
    "load": ("deserialization", "medium", "unsafe load() — verify loader (e.g. yaml.safe_load)"),
}


@dataclass
class DangerousCall:
    """A detected risky call or anti-pattern in Python source."""

    path: str
    name: str
    lineno: int
    kind: str
    severity: str
    message: str

    def format(self) -> str:
        """Return a single-line description."""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.kind}: "
            f"{self.name} — {self.message}"
        )


@dataclass
class DangerousCallStats:
    """Aggregate dangerous-call statistics."""

    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_unsafe_yaml_load(node: ast.Call) -> bool:
    name = _call_name(node)
    if name != "load":
        return False
    if isinstance(node.func, ast.Attribute):
        attr = node.func
        if isinstance(attr.value, ast.Name) and attr.value.id == "yaml":
            for kw in node.keywords:
                if kw.arg == "Loader":
                    return False
            return True
    return False


def _is_subprocess_shell_true(node: ast.Call) -> bool:
    name = _call_name(node)
    if name not in {"run", "call", "Popen", "check_output", "check_call"}:
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    if node.func.value.id != "subprocess":
        return False
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


class _DangerousCallVisitor(ast.NodeVisitor):
    """Walk a module AST and collect dangerous calls and anti-patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DangerousCall] = []
        self._function_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        name: str,
        kind: str,
        severity: str,
        message: str,
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            DangerousCall(
                path=self.path,
                name=name,
                lineno=lineno,
                kind=kind,
                severity=severity,
                message=message,
            )
        )

    def _qualified_name(self, name: str) -> str:
        if self._function_stack:
            return f"{self._function_stack[-1]}.{name}"
        return name

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        for default in node.args.defaults:
            if isinstance(default, ast.Constant) and default.value is Ellipsis:
                continue
            if isinstance(default, _MUTABLE_DEFAULT_TYPES):
                self._add(
                    default,
                    self._qualified_name(node.name),
                    "mutable_default",
                    "high",
                    "mutable default argument — use None and initialize inside the function",
                )
        for default in node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, _MUTABLE_DEFAULT_TYPES):
                self._add(
                    default,
                    self._qualified_name(node.name),
                    "mutable_default",
                    "high",
                    "mutable default argument — use None and initialize inside the function",
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name and name in _DANGEROUS_CALLS:
            kind, severity, message = _DANGEROUS_CALLS[name]
            if name == "load" and not _is_unsafe_yaml_load(node):
                pass
            elif name == "loads":
                if isinstance(node.func, ast.Attribute):
                    module = node.func.value
                    if isinstance(module, ast.Name) and module.id in {"pickle", "marshal"}:
                        self._add(node, name, kind, severity, message)
                elif isinstance(node.func, ast.Name):
                    self._add(node, name, kind, severity, message)
            elif name == "load":
                self._add(node, name, kind, severity, message)
            elif name == "system" and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    self._add(node, "os.system", kind, severity, message)
            elif name == "popen" and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    self._add(node, "os.popen", kind, severity, message)
            else:
                self._add(node, name, kind, severity, message)

        if _is_subprocess_shell_true(node):
            self._add(
                node,
                "subprocess(shell=True)",
                "shell_injection",
                "high",
                "subprocess with shell=True enables shell injection — pass a command list",
            )

        self.generic_visit(node)


class DangerousCallsAnalyzer:
    """Detect risky Python calls and anti-patterns in a project.

    Flags ``eval``/``exec``, shell injection via ``os.system`` or
    ``subprocess(shell=True)``, unsafe deserialization, unsafe ``yaml.load``,
    and mutable default arguments.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DangerousCall] = []
        self._stats: DangerousCallStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[DangerousCall]:
        """Analyze the project and return dangerous-call findings."""
        if self._findings:
            return self._findings

        findings: list[DangerousCall] = []
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
            visitor = _DangerousCallVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_kind: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = DangerousCallStats(
            total_findings=len(findings),
            by_kind=by_kind,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DangerousCallStats:
        """Return aggregate dangerous-call statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_kind(self, kind: str) -> list[DangerousCall]:
        """Return findings for a specific kind (e.g. code_injection, mutable_default)."""
        return [f for f in self.analyze() if f.kind == kind]

    def high_severity(self) -> list[DangerousCall]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no dangerous calls)."""
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
            f"Dangerous calls: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_kind:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_kind.items()))
            lines.append(f"By kind: {kinds}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing dangerous-call findings."""
        self.analyze()
        lines = [
            "Dangerous call analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No dangerous calls found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
