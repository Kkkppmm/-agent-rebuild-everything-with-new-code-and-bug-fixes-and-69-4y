"""GraphQLInjectionAnalyzer — detect string-built GraphQL queries vulnerable to injection."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_GRAPHQL_KEYWORDS = frozenset({"query", "mutation", "subscription", "fragment"})
_LINE_PATTERNS = (
    re.compile(r'f["\'].*\{.*\}.*(?:query|mutation)\s*\{', re.IGNORECASE),
    re.compile(r'["\'].*\{.*\}.*(?:query|mutation)\s*\{', re.IGNORECASE),
    re.compile(r"(?:query|mutation)\s*[=+].*\+"),
    re.compile(r"\.format\s*\([^)]*\).*(?:query|mutation)", re.IGNORECASE),
    re.compile(r"%\s*\([^)]*\).*(?:query|mutation)", re.IGNORECASE),
)


@dataclass
class GraphQLInjectionFinding:
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
class GraphQLInjectionStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_graphql(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _GRAPHQL_KEYWORDS) and "{" in text


class _GraphQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[GraphQLInjectionFinding] = []
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

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{}")
        text = "".join(parts)
        if _looks_like_graphql(text):
            self.findings.append(
                GraphQLInjectionFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="fstring_graphql",
                    severity="high",
                    message="GraphQL query built with f-string interpolation — use parameterized queries or a client library",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Add):
            left = self._extract_string(node.left)
            right = self._extract_string(node.right)
            combined = (left or "") + (right or "")
            if _looks_like_graphql(combined):
                self.findings.append(
                    GraphQLInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="concat_graphql",
                        severity="high",
                        message="GraphQL query built via string concatenation — use parameterized queries",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            base = self._extract_string(func.value)
            if base and _looks_like_graphql(base):
                self.findings.append(
                    GraphQLInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="format_graphql",
                        severity="high",
                        message="GraphQL query built with .format() — use parameterized queries",
                        function=self._current_function(),
                    )
                )
        if isinstance(func, ast.Attribute) and func.attr in {"execute", "query", "mutate"}:
            for arg in node.args:
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    pass  # handled by other visitors
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _looks_like_graphql(arg.value) and "{" in arg.value and "%" in arg.value:
                        self.findings.append(
                            GraphQLInjectionFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="dynamic_graphql_arg",
                                severity="medium",
                                message="Dynamic GraphQL argument may allow injection — validate and parameterize",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)

    @staticmethod
    def _extract_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    parts.append("{}")
            return "".join(parts)
        return None


class GraphQLInjectionAnalyzer:
    """Detect GraphQL queries built via string interpolation or concatenation."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[GraphQLInjectionFinding] = []
        self._stats: GraphQLInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[GraphQLInjectionFinding]:
        if self._findings:
            return self._findings

        findings: list[GraphQLInjectionFinding] = []
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
            visitor = _GraphQLInjectionVisitor(rel)
            visitor.visit(tree)

            for lineno, line in enumerate(source.splitlines(), start=1):
                for pattern_re in _LINE_PATTERNS:
                    if pattern_re.search(line):
                        pattern = "line_graphql_interpolation"
                        if not any(f.lineno == lineno for f in visitor.findings):
                            visitor.findings.append(
                                GraphQLInjectionFinding(
                                    path=rel,
                                    lineno=lineno,
                                    pattern=pattern,
                                    severity="high",
                                    message="GraphQL query built with string interpolation — use parameterized queries",
                                )
                            )

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
        self._stats = GraphQLInjectionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> GraphQLInjectionStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 12.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"GraphQL injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["GraphQL injection analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No GraphQL injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
