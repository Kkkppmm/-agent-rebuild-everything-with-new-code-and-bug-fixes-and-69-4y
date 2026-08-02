"""JWTSecurityAnalyzer — detect insecure JWT handling patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_MODULES = frozenset({"jwt", "jose", "jose_jwt"})
_NONE_ALGORITHM_VALUES = frozenset({"none", "None", "NONE"})
_DECODE_ATTRS = frozenset({"decode", "decode_complete"})
_ENCODE_ATTRS = frozenset({"encode"})


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


def _kw_bool(node: ast.AST, default: bool | None = None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return default


def _kw_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_jwt_call(node: ast.Call) -> bool:
    name = _call_name(node)
    parts = name.split(".")
    module = parts[0] if parts else ""
    method = parts[-1] if parts else ""
    return module in _JWT_MODULES and method in _DECODE_ATTRS | _ENCODE_ATTRS


class _JWTSecurityVisitor(ast.NodeVisitor):
    """Walk a module AST and collect JWT security risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[JWTSecurityFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.Call,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            JWTSecurityFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=_call_name(node),
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
        if not _is_jwt_call(node):
            self.generic_visit(node)
            return

        name = _call_name(node)
        method = name.split(".")[-1]
        call = _call_name(node)

        for kw in node.keywords:
            if kw.arg == "verify" and _kw_bool(kw.value) is False:
                self._add(
                    node,
                    "verify_disabled",
                    "critical",
                    "JWT signature verification disabled — tokens can be forged",
                )
            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for key, val in zip(kw.value.keys, kw.value.values):
                    key_str = _kw_string(key) if key else None
                    if key_str == "verify_signature" and _kw_bool(val) is False:
                        self._add(
                            node,
                            "verify_signature_disabled",
                            "critical",
                            "verify_signature=False allows forged JWT tokens",
                        )
                    if key_str == "verify_exp" and _kw_bool(val) is False:
                        self._add(
                            node,
                            "verify_exp_disabled",
                            "high",
                            "verify_exp=False allows expired tokens",
                        )

        if method == "encode":
            for kw in node.keywords:
                if kw.arg == "algorithm":
                    algo = _kw_string(kw.value)
                    if algo in _NONE_ALGORITHM_VALUES:
                        self._add(
                            node,
                            "none_algorithm",
                            "critical",
                            "JWT signed with 'none' algorithm — no integrity protection",
                        )
            if len(node.args) >= 3:
                algo = _kw_string(node.args[2])
                if algo in _NONE_ALGORITHM_VALUES:
                    self._add(
                        node,
                        "none_algorithm",
                        "critical",
                        "JWT signed with 'none' algorithm — no integrity protection",
                    )

        if method in _DECODE_ATTRS:
            for kw in node.keywords:
                if kw.arg == "algorithms":
                    if isinstance(kw.value, (ast.List, ast.Tuple)):
                        for elt in kw.value.elts:
                            algo = _kw_string(elt)
                            if algo in _NONE_ALGORITHM_VALUES:
                                self._add(
                                    node,
                                    "none_algorithm_accepted",
                                    "critical",
                                    "Accepting 'none' algorithm allows unsigned token forgery",
                                )

        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT handling in Python projects.

    Flags disabled signature verification, accepted 'none' algorithm,
    and other common JWT misconfigurations.
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
        """Return a 0-100 health score (100 = no JWT security issues)."""
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
        lines = ["JWT security analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure JWT handling patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
