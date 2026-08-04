"""InformationDisclosureAnalyzer — detect information disclosure in responses and logs."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "credential",
        "auth",
        "authorization",
    }
)
_TRACE_ATTRS = frozenset(
    {
        "format_exc",
        "print_exc",
        "format_exception",
        "format_stack",
        "print_stack",
    }
)


@dataclass
class InformationDisclosureFinding:
    """A potential information disclosure pattern."""

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
class InformationDisclosureStats:
    """Aggregate information-disclosure analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_sensitive_name(name: str) -> bool:
    lower = name.lower()
    return any(s in lower for s in _SENSITIVE_NAMES)


def _is_exception_var(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"e", "exc", "error", "exception", "err"}
    return False


class _InformationDisclosureVisitor(ast.NodeVisitor):
    """Walk a module AST and collect information disclosure risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InformationDisclosureFinding] = []
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
            InformationDisclosureFinding(
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
        if isinstance(func, ast.Attribute):
            if func.attr in _TRACE_ATTRS:
                self._add(
                    node,
                    func.attr,
                    severity="high",
                    message="Traceback exposed — avoid returning stack traces to clients",
                )
            if func.attr in {"jsonify", "JSONResponse", "HttpResponse"} and node.args:
                arg = node.args[0]
                if _is_exception_var(arg) or (
                    isinstance(arg, ast.Call)
                    and isinstance(arg.func, ast.Name)
                    and arg.func.id == "str"
                    and _is_exception_var(arg.args[0])
                ):
                    self._add(
                        node,
                        "error_in_response",
                        severity="high",
                        message="Exception details in API response — return generic error messages",
                    )
        if isinstance(func, ast.Name) and func.id in {"print", "repr"}:
            for arg in node.args:
                if isinstance(arg, ast.Name) and _is_sensitive_name(arg.id):
                    self._add(
                        node,
                        func.id,
                        severity="high",
                        message=f"Sensitive value '{arg.id}' may be disclosed via {func.id}()",
                    )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            if _is_exception_var(node.value):
                self._add(
                    node,
                    "return_exception",
                    severity="high",
                    message="Returning exception object — may leak internal details",
                )
            if isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Attribute) and func.attr in _TRACE_ATTRS:
                    self._add(
                        node,
                        "return_traceback",
                        severity="high",
                        message="Returning traceback text in response",
                    )
                if isinstance(func, ast.Name) and func.id == "str" and node.value.args:
                    if _is_exception_var(node.value.args[0]):
                        self._add(
                            node,
                            "return_str(exception)",
                            severity="high",
                            message="Returning str(exception) exposes internal error details",
                        )
        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect information disclosure in API responses and debug output.

    Flags traceback exposure, exception details in JSON responses, returning
    ``str(e)``, and printing/logging of sensitive values.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InformationDisclosureFinding] = []
        self._stats: InformationDisclosureStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InformationDisclosureFinding]:
        """Analyze the project and return information-disclosure findings."""
        if self._findings:
            return self._findings

        findings: list[InformationDisclosureFinding] = []
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
            visitor = _InformationDisclosureVisitor(rel)
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

        self._stats = InformationDisclosureStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InformationDisclosureStats:
        """Return aggregate information-disclosure statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InformationDisclosureFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no disclosure risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Information disclosure: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing information-disclosure findings."""
        self.analyze()
        lines = [
            "Information disclosure analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No information disclosure risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
