"""TimingAttackAnalyzer — detect non-constant-time secret comparisons."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_NAME_RE = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|signature|hmac|digest|otp|pin|"
    r"salt|credential|auth|session|csrf|nonce|bearer|private[_-]?key)",
    re.IGNORECASE,
)

_SAFE_PATH_PARTS = frozenset({"tests", "test", "testing"})


def _is_test_path(path: Path) -> bool:
    parts = path.parts
    if any(part in _SAFE_PATH_PARTS for part in parts):
        return True
    name = path.name
    return name.startswith("test_") or name.endswith("_test.py")


def _expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _expr_name(node.value)
    return ""


def _is_sensitive_name(name: str) -> bool:
    return bool(name and _SENSITIVE_NAME_RE.search(name))


def _is_literal(node: ast.AST) -> bool:
    return isinstance(node, (ast.Constant, ast.List, ast.Dict, ast.Set, ast.Tuple))


class _TimingAttackVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure secret comparisons."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TimingAttackFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            TimingAttackFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
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

    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1:
            self.generic_visit(node)
            return

        op = node.ops[0]
        if not isinstance(op, (ast.Eq, ast.NotEq)):
            self.generic_visit(node)
            return

        left_name = _expr_name(node.left)
        right_name = _expr_name(node.comparators[0]) if node.comparators else ""
        left_sensitive = _is_sensitive_name(left_name)
        right_sensitive = _is_sensitive_name(right_name)
        in_security_context = _is_sensitive_name(self._current_function())

        if not (left_sensitive or right_sensitive or in_security_context):
            self.generic_visit(node)
            return

        if _is_literal(node.left) and _is_literal(node.comparators[0]):
            self.generic_visit(node)
            return

        op_label = "==" if isinstance(op, ast.Eq) else "!="
        names = " / ".join(n for n in (left_name, right_name) if n) or "value"
        severity = "high" if (left_sensitive and right_sensitive) or in_security_context else "medium"
        self._add(
            node,
            "insecure_compare",
            severity,
            (
                f"Insecure secret comparison with {op_label} on {names} — "
                "use hmac.compare_digest() or secrets.compare_digest()"
            ),
        )
        self.generic_visit(node)


@dataclass
class TimingAttackFinding:
    """A detected non-constant-time secret comparison."""

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
class TimingAttackStats:
    """Aggregate timing-attack analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class TimingAttackAnalyzer:
    """Detect secret comparisons vulnerable to timing attacks.

    Flags uses of ``==`` and ``!=`` on passwords, tokens, API keys, and
    similar values instead of constant-time helpers like
    ``hmac.compare_digest()`` or ``secrets.compare_digest()``.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        include_tests: bool = False,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.include_tests = include_tests
        self._findings: list[TimingAttackFinding] = []
        self._stats: TimingAttackStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if not self.include_tests and _is_test_path(path):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[TimingAttackFinding]:
        """Analyze the project and return timing-attack findings."""
        if self._findings:
            return self._findings

        findings: list[TimingAttackFinding] = []
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
            visitor = _TimingAttackVisitor(rel)
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

        self._stats = TimingAttackStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TimingAttackStats:
        """Return aggregate timing-attack statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_pattern(self, pattern: str) -> list[TimingAttackFinding]:
        """Return findings for a specific pattern."""
        return [f for f in self.analyze() if f.pattern == pattern]

    def high_severity(self) -> list[TimingAttackFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no timing-attack risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 18.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Timing attacks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing timing-attack findings."""
        self.analyze()
        lines = [
            "Timing attack analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure secret comparisons found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
