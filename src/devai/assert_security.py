"""AssertSecurityAnalyzer — detect assert statements used for security checks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SECURITY_KEYWORDS = frozenset(
    {
        "auth",
        "authenticate",
        "authenticated",
        "authorization",
        "authorized",
        "permission",
        "admin",
        "role",
        "token",
        "password",
        "credential",
        "secret",
        "session",
        "login",
        "privilege",
        "is_admin",
        "is_authenticated",
        "has_permission",
        "check_permission",
        "superuser",
        "owner",
        "csrf",
        "jwt",
        "oauth",
    }
)


@dataclass
class AssertSecurityFinding:
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
class AssertSecurityStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_test_path(rel: str) -> bool:
    parts = Path(rel).parts
    if "tests" in parts or "test" in parts:
        return True
    name = Path(rel).name
    return name.startswith("test_") or name.endswith("_test.py")


def _name_from_node(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _expr_contains_security_keyword(node: ast.expr) -> bool:
    for child in ast.walk(node):
        name = _name_from_node(child)
        if name and name.lower() in _SECURITY_KEYWORDS:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            lowered = child.value.lower()
            if any(keyword in lowered for keyword in _SECURITY_KEYWORDS):
                return True
    return False


def _is_type_assert(test: ast.expr) -> bool:
    if isinstance(test, ast.Call):
        func = test.func
        if isinstance(func, ast.Name) and func.id == "isinstance":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "isinstance":
            return True
    return False


class _AssertSecurityVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[AssertSecurityFinding] = []
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

    def visit_Assert(self, node: ast.Assert) -> None:
        if _is_type_assert(node.test):
            return
        if _expr_contains_security_keyword(node.test):
            self.findings.append(
                AssertSecurityFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="security_assert",
                    severity="high",
                    message=(
                        "assert used for security check — assertions are stripped with -O "
                        "and PYTHONOPTIMIZE; raise an exception instead"
                    ),
                    function=self._current_function(),
                )
            )
        else:
            self.findings.append(
                AssertSecurityFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="production_assert",
                    severity="low",
                    message="assert in production code — use explicit validation or logging",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class AssertSecurityAnalyzer:
    """Detect assert statements used for security and authorization checks."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[AssertSecurityFinding] = []
        self._stats: AssertSecurityStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        rel = str(path.relative_to(self.root))
        return _is_test_path(rel)

    def analyze(self) -> list[AssertSecurityFinding]:
        if self._findings:
            return self._findings

        findings: list[AssertSecurityFinding] = []
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
            visitor = _AssertSecurityVisitor(rel)
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
        self._stats = AssertSecurityStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> AssertSecurityStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 3.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Assert security risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Assert security analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unsafe assert patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
