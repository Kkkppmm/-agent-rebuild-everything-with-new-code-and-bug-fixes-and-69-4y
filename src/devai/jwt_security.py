"""JWTSecurityAnalyzer — detect insecure JWT handling patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_MODULES = frozenset({"jwt", "jose", "jose.jwt", "authlib.jose"})
_DECODE_ATTRS = frozenset({"decode", "decode_jwt", "decode_complete"})
_NONE_ALGORITHMS = frozenset({"none", "None", "NONE"})


@dataclass
class JWTSecurityFinding:
    """A potentially insecure JWT handling pattern."""

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


def _is_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value is False:
        return True
    if isinstance(node, ast.NameConstant) and node.value is False:
        return True
    return False


def _has_none_algorithm(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "algorithms":
            value = kw.value
            if isinstance(value, ast.List):
                for elt in value.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                        return True
            if isinstance(value, ast.Constant) and str(value.value).lower() == "none":
                return True
    return False


def _has_verify_disabled(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg in {"verify", "verify_signature"} and _is_false(kw.value):
            return True
        if kw.arg == "options" and isinstance(kw.value, ast.Dict):
            for key, val in zip(kw.value.keys, kw.value.values):
                if key is None:
                    continue
                key_name = ""
                if isinstance(key, ast.Constant):
                    key_name = str(key.value)
                if key_name in {"verify_signature", "verify_exp", "verify_aud"} and _is_false(val):
                    return True
    return False


def _classify_jwt_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    attr = func.attr
    if attr not in _DECODE_ATTRS:
        return None

    module = _module_name(func.value)
    if not module:
        return None

    base = module.split(".")[0]
    if base not in {"jwt", "jose", "authlib"} and module not in _JWT_MODULES:
        return None

    if _has_none_algorithm(call):
        return (
            "jwt_alg_none",
            "critical",
            "JWT decoded with algorithm 'none' — allows unsigned token forgery",
        )

    if _has_verify_disabled(call):
        return (
            "jwt_verify_disabled",
            "critical",
            "JWT decoded without signature verification — tokens can be forged",
        )

    # jwt.decode with no key and no algorithms is risky (first arg is the token, not the key)
    has_key = len(call.args) > 1 or any(kw.arg in {"key", "public_key"} for kw in call.keywords)
    has_algorithms = any(kw.arg == "algorithms" for kw in call.keywords)
    if not has_key and not has_algorithms:
        return (
            "jwt_decode_no_key",
            "high",
            "JWT decode without key or algorithms — verify signature and restrict algorithms",
        )

    return None


class _JWTSecurityVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure JWT handling."""

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
        result = _classify_jwt_call(node)
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
    """Detect insecure JWT handling in Python projects.

    Flags jwt.decode with verify=False, algorithms=['none'], missing keys,
    and similar patterns that allow token forgery.
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

    def critical_findings(self) -> list[JWTSecurityFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure JWT handling)."""
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
            lines.append("No insecure JWT handling patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
