"""GraphQLInjectionAnalyzer — detect GraphQL injection and unsafe query construction."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_GRAPHQL_ATTRS = frozenset({"execute", "query", "mutate", "request", "graphql"})
_GRAPHQL_MODULES = frozenset({"gql", "graphql", "sgqlc", "ariadne"})
_LINE_PATTERNS = (
    re.compile(r'f["\'].*\{.*\}.*["\'].*(?:query|mutation|gql|graphql)', re.IGNORECASE),
    re.compile(r'(?:query|mutation)\s*=\s*f["\']'),
    re.compile(r'\.format\s*\([^)]*\).*(?:query|mutation|gql)'),
    re.compile(r'\+\s*["\'].*(?:query|mutation)'),
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


def _is_graphql_context(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return True
    return False


def _looks_like_graphql_string(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("query", "mutation", "subscription", "fragment"))


class _GraphQLInjectionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[GraphQLInjectionFinding] = []
        self._function_stack: list[str] = []
        self._has_graphql_import = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if any(mod in alias.name for mod in _GRAPHQL_MODULES):
                self._has_graphql_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and any(mod in node.module for mod in _GRAPHQL_MODULES):
            self._has_graphql_import = True
        self.generic_visit(node)

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
        is_graphql_call = False
        if isinstance(func, ast.Attribute) and func.attr in _GRAPHQL_ATTRS:
            is_graphql_call = True
        if isinstance(func, ast.Name) and func.id in {"gql", "graphql"}:
            is_graphql_call = True

        if is_graphql_call and node.args:
            arg = node.args[0]
            if _is_graphql_context(arg):
                self.findings.append(
                    GraphQLInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="dynamic_graphql_query",
                        severity="high",
                        message="GraphQL query built from dynamic strings — use variables/parameters",
                        function=self._current_function(),
                    )
                )
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if "%" in arg.value or "{" in arg.value:
                    self.findings.append(
                        GraphQLInjectionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="interpolated_graphql_query",
                            severity="high",
                            message="GraphQL query string contains interpolation placeholders",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in {"query", "mutation", "gql_query"}:
                if _is_graphql_context(node.value):
                    self.findings.append(
                        GraphQLInjectionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="dynamic_graphql_query",
                            severity="high",
                            message="GraphQL query assigned from dynamic string construction",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class GraphQLInjectionAnalyzer:
    """Detect GraphQL injection risks from unsafe query construction."""

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

    def _scan_line_patterns(self, rel: str, source: str) -> list[GraphQLInjectionFinding]:
        findings: list[GraphQLInjectionFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            if not any(token in line.lower() for token in ("query", "mutation", "graphql", "gql")):
                continue
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        GraphQLInjectionFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="dynamic_graphql_query",
                            severity="high",
                            message="GraphQL query may be built from user-controlled input",
                        )
                    )
                    break
        return findings

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
            line_findings = self._scan_line_patterns(rel, source)
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
        penalty = high * 25.0
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
