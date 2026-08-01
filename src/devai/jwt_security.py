"""JWTSecurityAnalyzer — detect insecure JWT handling patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_DECODE_FUNCS = frozenset(
    {
        "jwt.decode",
        "decode",
        "jwt_decode",
        "verify_jwt",
        "decode_token",
        "validate_token",
    }
)
_JWT_ENCODE_FUNCS = frozenset({"jwt.encode", "encode"})
_USER_INPUT_RE = re.compile(
    r"(request|user|input|token|payload|secret|key|header|auth|bearer)",
    re.IGNORECASE,
)


@dataclass
class JWTSecurityFinding:
    """An insecure JWT handling pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class JWTSecurityStats:
    """Aggregate JWT security analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    return False


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_string_literal(node: ast.AST, value: str | None = None) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return value is None or node.value == value
    return False


def _kw_value(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _check_jwt_call(node: ast.Call) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) for risky JWT operations."""
    name = _call_name(node)

    if name in _JWT_DECODE_FUNCS or name.endswith(".decode"):
        verify = _kw_value(node, "verify")
        if verify is not None and _is_false(verify):
            return (
                "jwt_verify_disabled",
                "critical",
                "JWT verification disabled — tokens can be forged",
            )

        algorithms = _kw_value(node, "algorithms")
        if algorithms is not None and isinstance(algorithms, (ast.List, ast.Tuple)):
            for elt in algorithms.elts:
                if _is_string_literal(elt, "none") or _is_string_literal(elt, "None"):
                    return (
                        "jwt_algorithm_none",
                        "critical",
                        "JWT algorithm 'none' allowed — signature bypass possible",
                    )

        options = _kw_value(node, "options")
        if options is not None and isinstance(options, ast.Dict):
            for key, val in zip(options.keys, options.values, strict=False):
                if isinstance(key, ast.Constant) and key.value == "verify_signature":
                    if _is_false(val):
                        return (
                            "jwt_signature_disabled",
                            "critical",
                            "JWT signature verification disabled via options",
                        )

    if name in _JWT_ENCODE_FUNCS or name.endswith(".encode"):
        algorithm = _kw_value(node, "algorithm")
        if algorithm is not None and _is_string_literal(algorithm, "none"):
            return (
                "jwt_encode_none",
                "critical",
                "JWT encoded with algorithm 'none' — unsigned tokens",
            )

        secret = _kw_value(node, "key") or (node.args[1] if len(node.args) > 1 else None)
        if secret is not None and _is_string_literal(secret):
            if len(secret.value) < 16:  # type: ignore[union-attr]
                return (
                    "jwt_weak_secret",
                    "high",
                    "Hardcoded JWT secret is too short — use a strong random key",
                )

    return None


def _check_hardcoded_secret_assign(node: ast.Assign) -> tuple[str, str, str] | None:
    for target in node.targets:
        if isinstance(target, ast.Name) and re.search(
            r"(jwt|token).*(secret|key)|secret.*(jwt|token)", target.id, re.IGNORECASE
        ):
            if _is_string_literal(node.value):
                return (
                    "jwt_hardcoded_secret",
                    "high",
                    "Hardcoded JWT secret — use environment variables or a secrets manager",
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

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str, call: str = "") -> None:
        self.findings.append(
            JWTSecurityFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=call,
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

    def visit_Call(self, node: ast.Call) -> None:
        result = _check_jwt_call(node)
        if result:
            pattern, severity, message = result
            self._add(node, pattern, severity, message, call=_call_name(node))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        result = _check_hardcoded_secret_assign(node)
        if result:
            pattern, severity, message = result
            self._add(node, pattern, severity, message)
        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT handling in Python projects.

    Flags disabled verification, algorithm-none, hardcoded secrets,
    and weak signing keys in jwt/PyJWT usage.
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

    def critical(self) -> list[JWTSecurityFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no JWT risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = critical * 30.0 + high * 15.0
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
            lines.append("No insecure JWT handling patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
