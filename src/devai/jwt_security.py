"""JWTSecurityAnalyzer — detect insecure JWT handling patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_MODULES = frozenset({"jwt", "jose", "authlib"})
_JWT_DECODE_ATTRS = frozenset({"decode", "decode_complete"})
_UNSAFE_OPTIONS = frozenset({"verify_signature", "verify_exp", "verify_aud", "verify_iss"})
_NONE_ALGORITHMS = frozenset({"none", "None", "NONE"})


@dataclass
class JWTSecurityFinding:
    """An insecure JWT handling pattern."""

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
class JWTSecurityStats:
    """Aggregate JWT security analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _module_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _is_jwt_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    attr = func.attr
    module = _module_name(func.value)
    if not module:
        return None

    base = module.split(".")[0]
    if base not in _JWT_MODULES:
        return None

    if attr in _JWT_DECODE_ATTRS:
        for kw in call.keywords:
            if kw.arg in _UNSAFE_OPTIONS:
                val = kw.value
                if isinstance(val, ast.Constant) and val.value is False:
                    return (
                        f"jwt_disabled_{kw.arg}",
                        "critical",
                        f"jwt.{attr}() with {kw.arg}=False bypasses security checks",
                    )
        for kw in call.keywords:
            if kw.arg == "options":
                if isinstance(kw.value, ast.Dict):
                    for key, val in zip(kw.value.keys, kw.value.values, strict=False):
                        if (
                            isinstance(key, ast.Constant)
                            and key.value in _UNSAFE_OPTIONS
                            and isinstance(val, ast.Constant)
                            and val.value is False
                        ):
                            return (
                                f"jwt_options_{key.value}",
                                "critical",
                                f"jwt.{attr}() options disable {key.value}",
                            )

    if attr == "encode":
        for arg in call.args:
            if isinstance(arg, ast.Dict):
                for key, val in zip(arg.keys, arg.values, strict=False):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "alg"
                        and isinstance(val, ast.Constant)
                        and val.value in _NONE_ALGORITHMS
                    ):
                        return (
                            "jwt_none_algorithm",
                            "critical",
                            "JWT signed with 'none' algorithm — tokens can be forged",
                        )
        for kw in call.keywords:
            if kw.arg == "algorithm":
                val = kw.value
                if isinstance(val, ast.Constant) and val.value in _NONE_ALGORITHMS:
                    return (
                        "jwt_none_algorithm",
                        "critical",
                        "JWT signed with 'none' algorithm — tokens can be forged",
                    )

    if attr in {"get_unverified_header", "get_unverified_claims"}:
        return (
            "jwt_unverified_access",
            "high",
            f"jwt.{attr}() reads token data without verification",
        )

    return None


class _JWTSecurityVisitor(ast.NodeVisitor):
    """Walk a module AST and collect JWT security risks."""

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

    def visit_Call(self, node: ast.Call) -> None:
        result = _is_jwt_call(node)
        if result:
            pattern, severity, message = result
            self.findings.append(
                JWTSecurityFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT handling in Python code.

    Flags disabled signature verification, 'none' algorithm usage,
    and unverified token access patterns.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
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
        """Analyze the project and return JWT security findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no JWT security issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = critical * 30.0 + high * 20.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"JWT security: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing JWT security findings."""
        self.analyze()
        lines = [
            "JWT security analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure JWT patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
