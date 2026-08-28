"""TimingAttackAnalyzer — detect non-constant-time secret comparisons."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|auth|signature|hash|"
    r"credential|private_key|access_key|session|nonce|otp|pin|key)",
    re.IGNORECASE,
)
_SAFE_COMPARE_FUNCS = frozenset(
    {"compare_digest", "compare_digest_hex", "secrets_compare_digest"}
)


@dataclass
class TimingAttackFinding:
    """A non-constant-time comparison of secret values."""

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


def _looks_like_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_SECRET_NAME_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_SECRET_NAME_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_secret(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _looks_like_secret(node.func)
    return False


def _is_safe_compare_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _SAFE_COMPARE_FUNCS:
            return True
        if isinstance(func, ast.Name) and func.id in _SAFE_COMPARE_FUNCS:
            return True
    return False


def _classify_compare(node: ast.Compare) -> tuple[str, str, str] | None:
    if len(node.ops) != 1:
        return None
    op = node.ops[0]
    if not isinstance(op, (ast.Eq, ast.NotEq)):
        return None

    left_secret = _looks_like_secret(node.left)
    right_secret = any(_looks_like_secret(c) for c in node.comparators)

    if not left_secret and not right_secret:
        return None

    op_type = "eq_compare" if isinstance(op, ast.Eq) else "ne_compare"
    return (
        op_type,
        "medium",
        "Secret comparison with ==/!= is vulnerable to timing attacks — use hmac.compare_digest()",
    )


class _TimingAttackVisitor(ast.NodeVisitor):
    """Walk a module AST and collect timing-attack risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TimingAttackFinding] = []
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

    def visit_Compare(self, node: ast.Compare) -> None:
        if _is_safe_compare_call(node):
            self.generic_visit(node)
            return
        result = _classify_compare(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                TimingAttackFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class TimingAttackAnalyzer:
    """Detect non-constant-time comparisons of secrets, tokens, and passwords.

    Flags == and != comparisons on security-sensitive values that should use
    hmac.compare_digest() to prevent timing side-channel attacks.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TimingAttackFinding] = []
        self._stats: TimingAttackStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no timing-attack risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = medium * 12.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Timing attack risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
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
            lines.append("No timing-attack patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
