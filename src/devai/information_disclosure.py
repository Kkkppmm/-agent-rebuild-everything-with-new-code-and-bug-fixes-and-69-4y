"""InformationDisclosureAnalyzer — detect sensitive data exposure in responses and logs."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_ATTRS = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "private_key",
        "ssn",
        "credit_card",
        "__dict__",
        "vars",
    }
)
_USER_INPUT_NAMES = frozenset(
    {
        "request",
        "user",
        "data",
        "payload",
        "body",
        "error",
        "exception",
        "exc",
        "e",
    }
)
_LINE_PATTERNS = (
    re.compile(r"return\s+.*traceback\.format_exc"),
    re.compile(r"jsonify\s*\(\s*vars\s*\("),
    re.compile(r"return\s+.*\.__dict__"),
)


@dataclass
class InformationDisclosureFinding:
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
class InformationDisclosureStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_user_controlled(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _USER_INPUT_NAMES or node.id.endswith("_input")
    if isinstance(node, ast.Attribute):
        if node.attr in {"args", "form", "values", "GET", "POST", "json", "data"}:
            return True
        return _is_user_controlled(node.value)
    if isinstance(node, ast.Subscript):
        return _is_user_controlled(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            return _is_user_controlled(func.value)
    return False


class _InformationDisclosureVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InformationDisclosureFinding] = []
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        value = node.value
        if isinstance(value, ast.Call):
            func = value.func
            if isinstance(func, ast.Attribute) and func.attr == "format_exc":
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="traceback_in_response",
                        severity="high",
                        message="Returning traceback exposes internal stack traces to users",
                        function=self._current_function(),
                    )
                )
            if isinstance(func, ast.Name) and func.id == "vars":
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="vars_in_response",
                        severity="high",
                        message="Returning vars() may expose internal object state",
                        function=self._current_function(),
                    )
                )
        if isinstance(value, ast.Attribute) and value.attr == "__dict__":
            self.findings.append(
                InformationDisclosureFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="dict_in_response",
                    severity="medium",
                    message="Returning __dict__ may leak sensitive object fields",
                    function=self._current_function(),
                )
            )
        if isinstance(value, ast.Name) and value.id in {"error", "exception", "exc", "e"}:
            self.findings.append(
                InformationDisclosureFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="exception_in_response",
                    severity="medium",
                    message="Returning raw exception objects may disclose internal details",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Attribute) and arg.attr in _SENSITIVE_ATTRS:
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="sensitive_print",
                        severity="medium",
                        message=f"Printing sensitive attribute '{arg.attr}' may leak secrets to logs",
                        function=self._current_function(),
                    )
                )
        if isinstance(func, ast.Attribute) and func.attr == "jsonify" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "vars":
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="jsonify_vars",
                        severity="high",
                        message="jsonify(vars(...)) exposes internal object state in API responses",
                        function=self._current_function(),
                    )
                )
            if isinstance(arg, ast.Attribute) and arg.attr == "__dict__":
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="jsonify_dict",
                        severity="medium",
                        message="jsonify(__dict__) may leak sensitive fields in API responses",
                        function=self._current_function(),
                    )
                )
            if _is_user_controlled(arg):
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unfiltered_jsonify",
                        severity="low",
                        message="jsonify with unfiltered user input may expose unexpected data",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect information disclosure risks in API responses and logging."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InformationDisclosureFinding] = []
        self._stats: InformationDisclosureStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[InformationDisclosureFinding]:
        findings: list[InformationDisclosureFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    if "traceback" in pattern.pattern:
                        ptype, msg = (
                            "traceback_in_response",
                            "Returning traceback exposes internal stack traces to users",
                        )
                    elif "vars" in pattern.pattern:
                        ptype, msg = (
                            "jsonify_vars",
                            "jsonify(vars(...)) exposes internal object state in API responses",
                        )
                    else:
                        ptype, msg = (
                            "dict_in_response",
                            "Returning __dict__ may leak sensitive object fields",
                        )
                    findings.append(
                        InformationDisclosureFinding(
                            path=rel,
                            lineno=lineno,
                            pattern=ptype,
                            severity="high" if ptype != "dict_in_response" else "medium",
                            message=msg,
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[InformationDisclosureFinding]:
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
            line_findings = self._scan_line_patterns(rel, source)
            all_findings = visitor.findings + line_findings
            if all_findings:
                files_with_findings.add(rel)
            findings.extend(all_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Information disclosure risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Information disclosure analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No information disclosure patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
