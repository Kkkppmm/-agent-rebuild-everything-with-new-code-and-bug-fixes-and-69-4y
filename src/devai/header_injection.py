"""HeaderInjectionAnalyzer — detect HTTP response header injection (CRLF) risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HEADER_ATTRS = frozenset(
    {
        "headers",
        "set_header",
        "add_header",
        "append",
        "setdefault",
        "set_cookie",
        "setcookie",
        "redirect",
        "make_response",
    }
)
_USER_INPUT_NAMES = frozenset(
    {
        "request",
        "user_input",
        "input",
        "data",
        "query",
        "params",
        "payload",
        "value",
        "name",
        "header",
        "location",
        "url",
        "redirect_url",
        "next",
        "return_url",
    }
)
_LINE_PATTERNS = (
    re.compile(r"\\r\\n"),
    re.compile(r"\\n.*:"),
    re.compile(r"headers\s*\[\s*['\"].*['\"]\s*\]\s*=\s*f?['\"].*\{"),
)


@dataclass
class HeaderInjectionFinding:
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
class HeaderInjectionStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_user_controlled(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _USER_INPUT_NAMES or node.id.endswith("_input")
    if isinstance(node, ast.Attribute):
        if node.attr in {"args", "form", "values", "GET", "POST", "query_params", "data", "json", "headers"}:
            return True
        return _is_user_controlled(node.value)
    if isinstance(node, ast.Subscript):
        return _is_user_controlled(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            return _is_user_controlled(func.value)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _is_user_controlled(v.value) for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    return False


class _HeaderInjectionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HeaderInjectionFinding] = []
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

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Attribute) and node.value.attr == "headers":
            if isinstance(node.ctx, ast.Store) and isinstance(node.slice, ast.Constant):
                self.findings.append(
                    HeaderInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="header_subscript_assign",
                        severity="medium",
                        message="Direct header assignment via subscript may allow CRLF injection",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _HEADER_ATTRS:
            for arg in node.args:
                if _is_user_controlled(arg):
                    pattern = "redirect_user_input" if func.attr == "redirect" else "header_user_input"
                    message = (
                        "redirect() with user-controlled URL enables open redirect and header injection"
                        if func.attr == "redirect"
                        else f"{func.attr}() with user-controlled value may enable CRLF header injection"
                    )
                    self.findings.append(
                        HeaderInjectionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern=pattern,
                            severity="high",
                            message=message,
                            function=self._current_function(),
                        )
                    )
                    break
            for kw in node.keywords:
                if kw.arg in {"value", "location", "url", "header", "name"} and _is_user_controlled(kw.value):
                    self.findings.append(
                        HeaderInjectionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="header_kwarg_user_input",
                            severity="high",
                            message=f"{func.attr}({kw.arg}=...) with user input may enable CRLF injection",
                            function=self._current_function(),
                        )
                    )
        if isinstance(func, ast.Name) and func.id == "redirect" and node.args:
            if _is_user_controlled(node.args[0]):
                self.findings.append(
                    HeaderInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="redirect_user_input",
                        severity="high",
                        message="redirect() with user-controlled URL enables open redirect and header injection",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class HeaderInjectionAnalyzer:
    """Detect HTTP response header injection (CRLF) risks in Python web apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HeaderInjectionFinding] = []
        self._stats: HeaderInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[HeaderInjectionFinding]:
        findings: list[HeaderInjectionFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        HeaderInjectionFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="crlf_in_header_string",
                            severity="high",
                            message="Header value contains CRLF characters — enables HTTP response splitting",
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[HeaderInjectionFinding]:
        if self._findings:
            return self._findings

        findings: list[HeaderInjectionFinding] = []
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
            visitor = _HeaderInjectionVisitor(rel)
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
        self._stats = HeaderInjectionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HeaderInjectionStats:
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
            f"Header injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Header injection analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No header injection patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
