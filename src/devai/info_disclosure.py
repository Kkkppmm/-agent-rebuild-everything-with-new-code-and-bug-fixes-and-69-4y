"""InformationDisclosureAnalyzer — detect sensitive data exposure in API responses."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|private_key|"
    r"access_key|ssn|social_security|credit_card|cvv|pin|auth)",
    re.IGNORECASE,
)
_RESPONSE_FUNCS = frozenset(
    {
        "jsonify",
        "JSONResponse",
        "Response",
        "HttpResponse",
        "make_response",
        "render_template_string",
    }
)
_TRACEBACK_ATTRS = frozenset({"format_exc", "print_exc", "format_exception"})


@dataclass
class InformationDisclosureFinding:
    """A sensitive data exposure in a client-facing response."""

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


def _is_response_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in _RESPONSE_FUNCS:
        return True
    if isinstance(func, ast.Attribute) and func.attr in _RESPONSE_FUNCS:
        return True
    return False


def _is_return_stmt(node: ast.stmt) -> bool:
    return isinstance(node, ast.Return)


def _dict_has_sensitive_key(node: ast.Dict) -> bool:
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if _SENSITIVE_KEY_RE.search(key.value):
                return True
    return False


def _is_traceback_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _TRACEBACK_ATTRS:
            return True
    return False


def _contains_traceback(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if _is_traceback_call(child):
            return True
    return False


def _is_exception_str(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "str":
            if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in ("e", "exc", "error"):
                return True
    return False


class _InformationDisclosureVisitor(ast.NodeVisitor):
    """Walk a module AST and collect information-disclosure risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InformationDisclosureFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            InformationDisclosureFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            self.generic_visit(node)
            return
        if _contains_traceback(node.value):
            self._add(
                node,
                "traceback_in_response",
                "high",
                "Returning traceback data exposes internal error details to clients",
            )
        elif isinstance(node.value, ast.Dict) and _dict_has_sensitive_key(node.value):
            self._add(
                node,
                "sensitive_field_in_response",
                "high",
                "Returning dict with sensitive field names may leak credentials",
            )
        elif _is_exception_str(node.value):
            self._add(
                node,
                "exception_message_in_response",
                "medium",
                "Returning raw exception message may expose internal details",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_response_call(node):
            for arg in node.args:
                if _contains_traceback(arg):
                    self._add(
                        node,
                        "traceback_in_response",
                        "high",
                        "Including traceback in HTTP response exposes internal error details",
                    )
                    break
                if isinstance(arg, ast.Dict) and _dict_has_sensitive_key(arg):
                    self._add(
                        node,
                        "sensitive_field_in_response",
                        "high",
                        "Including sensitive fields in HTTP response may leak credentials",
                    )
                    break
                if _is_exception_str(arg):
                    self._add(
                        node,
                        "exception_message_in_response",
                        "medium",
                        "Including raw exception message in HTTP response may expose internals",
                    )
                    break
        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect sensitive data exposure in API and HTTP responses.

    Flags tracebacks, exception messages, and sensitive fields (password,
    token, secret) returned to clients via return statements or response helpers.
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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no disclosure risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Information disclosure risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
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
            lines.append("No information-disclosure patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
