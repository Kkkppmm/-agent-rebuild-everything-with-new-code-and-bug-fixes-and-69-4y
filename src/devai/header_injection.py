"""HeaderInjectionAnalyzer — detect HTTP header injection from user-controlled values."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HEADER_SET_ATTRS = frozenset(
    {
        "set",
        "add",
        "append",
        "setdefault",
        "set_cookie",
        "delete_cookie",
        "set_header",
        "add_header",
    }
)
_RESPONSE_OBJECTS = frozenset(
    {
        "response",
        "headers",
        "resp",
        "res",
    }
)
_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.query_params",
        "request.path_params",
        "request.headers",
        "request.cookies",
    }
)


@dataclass
class HeaderInjectionFinding:
    """A potentially unsafe HTTP header value from user input."""

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
class HeaderInjectionStats:
    """Aggregate header injection analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_request_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base and node.attr in {
            "args",
            "form",
            "values",
            "GET",
            "POST",
            "query_params",
            "path_params",
            "headers",
            "cookies",
        }:
            return True
    if isinstance(node, ast.Subscript) and _is_request_access(node.value):
        return True
    return _request_source(node) == "request"


def _is_user_controlled(node: ast.AST) -> bool:
    if _is_request_access(node):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "pop", "getlist"}:
            if _is_request_access(func.value):
                return True
    if isinstance(node, ast.JoinedStr):
        return any(
            _is_user_controlled(v.value) for v in node.values if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Name):
        return node.id in {
            "user_input",
            "header_value",
            "cookie_value",
            "location",
            "redirect_url",
            "filename",
        }
    return False


def _is_header_set_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _HEADER_SET_ATTRS:
        if isinstance(func.value, ast.Name) and func.value.id in _RESPONSE_OBJECTS:
            return True
        if isinstance(func.value, ast.Attribute):
            if isinstance(func.value.value, ast.Name) and func.value.value.id in _RESPONSE_OBJECTS:
                return True
    if isinstance(func, ast.Name) and func.id in {"make_response", "Response"}:
        return bool(node.args)
    return False


def _classify_header_call(node: ast.Call) -> tuple[str, str, str] | None:
    if not _is_header_set_call(node):
        return None

    func = node.func
    attr = ""
    if isinstance(func, ast.Attribute):
        attr = func.attr

    if attr == "set_cookie" and len(node.args) >= 2:
        if _is_user_controlled(node.args[1]):
            return (
                "cookie_value_injection",
                "high",
                "Cookie value from user input — sanitize to prevent header injection",
            )

    value_args = node.args[1:] if attr in {"set", "add", "append", "setdefault", "set_header", "add_header"} else node.args
    if not value_args and attr not in {"set_cookie"}:
        value_args = node.args

    for arg in value_args:
        if _is_user_controlled(arg):
            pattern = f"{attr}_user_value" if attr else "response_header_user_value"
            return (
                pattern,
                "high",
                "HTTP header value appears user-controlled — validate and strip CR/LF characters",
            )

    if node.keywords:
        for kw in node.keywords:
            if kw.arg in {"value", "content", "domain", "path"} and _is_user_controlled(kw.value):
                return (
                    f"{attr}_{kw.arg}_injection",
                    "high",
                    f"Header/cookie {kw.arg} from user input — sanitize before setting",
                )

    return None


class _HeaderInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect HTTP header injection risks."""

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

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_header_call(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                HeaderInjectionFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class HeaderInjectionAnalyzer:
    """Detect HTTP header injection risks in web framework handlers.

    Flags Flask/Django/FastAPI response header and cookie setters that pass
    user-controlled values without sanitization.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HeaderInjectionFinding] = []
        self._stats: HeaderInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[HeaderInjectionFinding]:
        """Analyze the project and return header injection findings."""
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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[HeaderInjectionFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no header injection risks)."""
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
        lines = [
            f"Header injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing header injection findings."""
        self.analyze()
        lines = [
            "Header injection analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No header injection patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
