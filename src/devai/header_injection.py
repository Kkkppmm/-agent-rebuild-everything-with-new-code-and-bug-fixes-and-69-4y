"""HeaderInjectionAnalyzer — detect HTTP header injection risks."""

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
        "setdefault",
        "append",
    }
)
_HEADER_NAMES = frozenset(
    {
        "Location",
        "Set-Cookie",
        "Content-Disposition",
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Custom",
        "X-",
    }
)
_USER_INPUT_NAMES = frozenset(
    {
        "request",
        "user_input",
        "data",
        "payload",
        "query",
        "name",
        "input",
        "text",
        "value",
        "url",
        "redirect",
        "header",
        "headers",
    }
)
_LINE_PATTERNS = (
    re.compile(r"response\.headers\[[^\]]+\]\s*="),
    re.compile(r"\.set_header\s*\("),
    re.compile(r"Location['\"]?\s*:\s*.*\+"),
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                base = target.value
                if isinstance(base, ast.Attribute) and base.attr == "headers":
                    if _is_user_controlled(node.value):
                        self.findings.append(
                            HeaderInjectionFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="response_header_assign",
                                severity="high",
                                message="User-controlled value assigned to response header enables header injection",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"set_header", "add_header"}:
            if len(node.args) >= 2 and _is_user_controlled(node.args[1]):
                self.findings.append(
                    HeaderInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="set_header_user_input",
                        severity="high",
                        message="User-controlled value passed to set_header/add_header enables header injection",
                        function=self._current_function(),
                    )
                )
        if isinstance(func, ast.Name) and func.id == "redirect":
            if node.args and _is_user_controlled(node.args[0]):
                self.findings.append(
                    HeaderInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="redirect_user_input",
                        severity="medium",
                        message="User-controlled redirect URL may enable header injection via Location header",
                        function=self._current_function(),
                    )
                )
        if isinstance(func, ast.Attribute) and func.attr == "redirect":
            if node.args and _is_user_controlled(node.args[0]):
                self.findings.append(
                    HeaderInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="redirect_user_input",
                        severity="medium",
                        message="User-controlled redirect URL may enable header injection via Location header",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class HeaderInjectionAnalyzer:
    """Detect HTTP header injection risks in Python web applications."""

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

    def _scan_line_patterns(self, rel: str, lines: list[str]) -> list[HeaderInjectionFinding]:
        findings: list[HeaderInjectionFinding] = []
        for lineno, line in enumerate(lines, start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line) and ("request" in line or "input" in line or "+" in line):
                    findings.append(
                        HeaderInjectionFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="line_header_injection",
                            severity="medium",
                            message="Possible header injection via dynamic header assignment",
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
            line_findings = self._scan_line_patterns(rel, source.splitlines())
            combined = visitor.findings + line_findings
            if combined:
                files_with_findings.add(rel)
            findings.extend(combined)

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
