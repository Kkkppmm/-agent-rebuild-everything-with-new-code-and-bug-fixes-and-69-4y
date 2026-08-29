"""WeakPasswordAnalyzer — detect weak password handling and validation."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PASSWORD_ATTRS = frozenset({"password", "passwd", "pwd", "pass"})
_WEAK_CHECKS = re.compile(r"len\s*\(\s*\w+\s*\)\s*[<>=]+\s*[1-7]\b")
_HASH_FUNCS = frozenset({"hash", "hashpw", "checkpw", "bcrypt", "argon2", "scrypt"})
_PLAINTEXT_PATTERNS = (
    re.compile(r"password\s*=\s*request"),
    re.compile(r"\.password\s*=\s*"),
    re.compile(r"store.*password.*plain", re.IGNORECASE),
)


@dataclass
class WeakPasswordFinding:
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
class WeakPasswordStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _WeakPasswordVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakPasswordFinding] = []
        self._function_stack: list[str] = []
        self._has_hash_func = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if any(h in alias.name.lower() for h in ("bcrypt", "argon2", "scrypt", "passlib")):
                self._has_hash_func = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and any(h in node.module.lower() for h in ("bcrypt", "argon2", "scrypt", "passlib")):
            self._has_hash_func = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Compare(self, node: ast.Compare) -> None:
        left = node.left
        if isinstance(left, ast.Call) and isinstance(left.func, ast.Name):
            if left.func.id == "len" and left.args:
                for op, comparator in zip(node.ops, node.comparators, strict=False):
                    weak_threshold = False
                    if isinstance(op, (ast.Lt, ast.LtE)) and isinstance(comparator, ast.Constant):
                        if isinstance(comparator.value, int) and comparator.value <= 8:
                            weak_threshold = True
                    if isinstance(op, ast.GtE) and isinstance(comparator, ast.Constant):
                        if isinstance(comparator.value, int) and comparator.value < 8:
                            weak_threshold = True
                    if weak_threshold and _is_password_var(left.args[0]):
                        self.findings.append(
                            WeakPasswordFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="weak_length_check",
                                severity="medium",
                                message="Password length check allows passwords shorter than 8 characters",
                                function=self._current_function(),
                            )
                        )
                        break
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr in _PASSWORD_ATTRS:
                if not self._is_hashed_value(node.value):
                    self.findings.append(
                        WeakPasswordFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="plaintext_password",
                            severity="high",
                            message="Password stored or assigned without hashing",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def _is_hashed_value(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _HASH_FUNCS:
                return True
            if isinstance(func, ast.Attribute) and func.attr in _HASH_FUNCS:
                return True
        return False


def _is_password_var(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and any(p in node.id.lower() for p in _PASSWORD_ATTRS):
        return True
    if isinstance(node, ast.Attribute) and node.attr in _PASSWORD_ATTRS:
        return True
    return False


class WeakPasswordAnalyzer:
    """Detect weak password validation and plaintext password storage."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[WeakPasswordFinding] = []
        self._stats: WeakPasswordStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[WeakPasswordFinding]:
        findings: list[WeakPasswordFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            if _WEAK_CHECKS.search(line):
                findings.append(
                    WeakPasswordFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="weak_length_check",
                        severity="medium",
                        message="Password length check may allow weak passwords",
                    )
                )
            for pattern in _PLAINTEXT_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        WeakPasswordFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="plaintext_password",
                            severity="high",
                            message="Password may be stored or handled in plaintext",
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[WeakPasswordFinding]:
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Weak password risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Weak password analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No weak password handling found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
