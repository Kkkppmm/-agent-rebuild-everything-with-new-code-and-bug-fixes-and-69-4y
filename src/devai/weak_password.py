"""WeakPasswordAnalyzer — detect weak password policies and plaintext storage."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PASSWORD_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "user_password",
        "new_password",
        "plain_password",
    }
)
_HASH_FUNCS = frozenset(
    {
        "generate_password_hash",
        "hash_password",
        "make_password",
        "set_password",
        "bcrypt",
        "hashpw",
        "pbkdf2_hmac",
        "scrypt",
        "argon2",
        "check_password_hash",
    }
)
_WEAK_MIN_LENGTH = 8


@dataclass
class WeakPasswordFinding:
    """A weak password policy or storage pattern."""

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
class WeakPasswordStats:
    """Aggregate weak-password analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_password_name(name: str) -> bool:
    lower = name.lower()
    return lower in _PASSWORD_NAMES or "password" in lower


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _is_hash_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        attr = _call_attr(node)
        if attr in _HASH_FUNCS:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _HASH_FUNCS:
            return True
    return False


def _password_var(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and _is_password_name(node.id):
        return True
    if isinstance(node, ast.Attribute) and _is_password_name(node.attr):
        return True
    return False


class _WeakPasswordVisitor(ast.NodeVisitor):
    """Walk a module AST and collect weak password patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakPasswordFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            WeakPasswordFinding(
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

    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1 or not isinstance(node.ops[0], ast.Lt):
            self.generic_visit(node)
            return
        for side in [node.left, *node.comparators]:
            if isinstance(side, ast.Call) and _call_attr(side) == "len":
                if side.args and _password_var(side.args[0]):
                    threshold = None
                    other = node.comparators[0] if side is node.left else node.left
                    if isinstance(other, ast.Constant) and isinstance(other.value, int):
                        threshold = other.value
                    if threshold is not None and threshold < _WEAK_MIN_LENGTH:
                        self._add(
                            node,
                            "weak_min_length",
                            severity="medium",
                            message=f"Password minimum length {threshold} is below recommended {_WEAK_MIN_LENGTH}",
                        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_hash_call(node.value):
            self.generic_visit(node)
            return
        for target in node.targets:
            if isinstance(target, ast.Attribute) and _is_password_name(target.attr):
                if _password_var(node.value) or (
                    isinstance(node.value, ast.Name) and _is_password_name(node.value.id)
                ):
                    self._add(
                        node,
                        "plaintext_storage",
                        severity="high",
                        message="Password stored without hashing — use bcrypt, scrypt, or argon2",
                    )
            if isinstance(target, ast.Name) and _is_password_name(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._add(
                        node,
                        "hardcoded_password",
                        severity="high",
                        message="Hardcoded password literal — use environment variables or a secrets manager",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        attr = _call_attr(node)
        if attr in {"create_user", "register", "signup", "set_password"}:
            has_hash = any(_is_hash_call(arg) for arg in node.args)
            has_password_arg = any(
                isinstance(arg, ast.keyword)
                and arg.arg
                and _is_password_name(arg.arg)
                and not _is_hash_call(arg.value)
                for arg in node.keywords
            )
            if has_password_arg and not has_hash:
                self._add(
                    node,
                    "unhashed_registration",
                    severity="high",
                    message="User registration passes plaintext password — hash before storage",
                )
        self.generic_visit(node)


class WeakPasswordAnalyzer:
    """Detect weak password policies and insecure password storage.

    Flags short minimum-length requirements, plaintext password storage,
    hardcoded passwords, and registration flows that skip hashing.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[WeakPasswordFinding] = []
        self._stats: WeakPasswordStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[WeakPasswordFinding]:
        """Analyze the project and return weak-password findings."""
        if self._findings:
            return self._findings

        findings: list[WeakPasswordFinding] = []
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
            visitor = _WeakPasswordVisitor(rel)
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

        self._stats = WeakPasswordStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> WeakPasswordStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no weak-password risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 12.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Weak password risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing weak-password findings."""
        self.analyze()
        lines = [
            "Weak password analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No weak-password patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
