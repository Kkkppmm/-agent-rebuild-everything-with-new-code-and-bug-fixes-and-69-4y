"""JWTSecurityAnalyzer — detect insecure JWT decode and hardcoded secrets."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_DECODE_ATTRS = frozenset({"decode", "decode_complete"})
_JWT_MODULES = frozenset({"jwt", "jose", "jose.jwt"})


@dataclass
class JWTSecurityFinding:
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
class JWTSecurityStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_jwt_decode(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in _DECODE_ATTRS:
        return False
    if isinstance(node.func.value, ast.Name) and node.func.value.id in {"jwt", "JWT"}:
        return True
    if isinstance(node.func.value, ast.Attribute):
        base = node.func.value
        if isinstance(base.value, ast.Name) and base.value.id in {"jwt", "jose"}:
            return True
    return False


def _has_verify_disabled(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg in {"verify", "options"} and isinstance(kw.value, ast.Constant):
            if kw.value.value is False:
                return True
        if kw.arg == "options" and isinstance(kw.value, ast.Dict):
            for key, val in zip(kw.value.keys, kw.value.values):
                if (
                    key
                    and isinstance(key, ast.Constant)
                    and key.value == "verify_signature"
                    and isinstance(val, ast.Constant)
                    and val.value is False
                ):
                    return True
    return False


def _is_hardcoded_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 8
    return False


class _JWTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[JWTSecurityFinding] = []
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
            if isinstance(target, ast.Name) and "secret" in target.id.lower():
                if _is_hardcoded_secret(node.value):
                    self.findings.append(
                        JWTSecurityFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="hardcoded_secret",
                            severity="high",
                            message="Hardcoded JWT secret — use environment variables",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_jwt_decode(node):
            if _has_verify_disabled(node):
                self.findings.append(
                    JWTSecurityFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="verify_disabled",
                        severity="high",
                        message="JWT signature verification disabled",
                        function=self._current_function(),
                    )
                )
            elif len(node.args) >= 2 and _is_hardcoded_secret(node.args[1]):
                self.findings.append(
                    JWTSecurityFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="inline_secret",
                        severity="high",
                        message="JWT secret passed as inline string literal",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT handling: disabled verification and hardcoded secrets."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[JWTSecurityFinding] = []
        self._stats: JWTSecurityStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[JWTSecurityFinding]:
        if self._findings:
            return self._findings

        findings: list[JWTSecurityFinding] = []
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
            visitor = _JWTSecurityVisitor(rel)
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
        self._stats = JWTSecurityStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> JWTSecurityStats:
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
            f"JWT security risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["JWT security analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No JWT security issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
