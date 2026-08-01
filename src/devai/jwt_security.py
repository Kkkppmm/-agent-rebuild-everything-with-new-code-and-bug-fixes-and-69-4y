"""JWTSecurityAnalyzer — detect insecure JSON Web Token handling."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_JWT_MODULES = frozenset({"jwt", "jose", "jose.jwt", "authlib.jose"})
_SECRET_RE = re.compile(
    r"(secret|key|signing|jwt|token|private)",
    re.IGNORECASE,
)
_WEAK_ALGORITHMS = frozenset({"none", "HS256", "HS384", "HS512"})


@dataclass
class JWTSecurityFinding:
    """A detected JWT security issue."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        call = f" ({self.call})" if self.call else ""
        return (
            f"{self.path}:{self.lineno}{call} [{self.severity}] "
            f"{self.pattern}: {self.message}"
        )


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


def _is_jwt_call(name: str) -> bool:
    short = name.split(".")[-1]
    if short in {
        "decode",
        "encode",
        "get_unverified_header",
        "get_unverified_claims",
    }:
        return True
    return name.endswith(".decode") or name.endswith(".encode")


def _is_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value is False:
        return True
    if isinstance(node, ast.NameConstant) and node.value is False:
        return True
    return False


def _is_string_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _kwarg_value(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _dict_has_false_verify(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == "verify_signature":
            return _is_false(value)
    return False


def _algorithm_is_none(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and str(node.value).lower() == "none":
        return True
    if isinstance(node, ast.List):
        return any(_algorithm_is_none(elt) for elt in node.elts)
    return False


def _looks_like_secret_name(name: str) -> bool:
    return bool(_SECRET_RE.search(name))


class _JWTSecurityVisitor(ast.NodeVisitor):
    """Walk a module AST and collect JWT security issues."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[JWTSecurityFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            JWTSecurityFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                call=call,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if not _is_jwt_call(name):
            self.generic_visit(node)
            return

        short = name.split(".")[-1]
        call_label = name

        if short in {"get_unverified_header", "get_unverified_claims"}:
            self._add(
                node,
                "unverified_jwt_access",
                severity="medium",
                message="Reading JWT claims without verification bypasses signature checks",
                call=call_label,
            )

        if short == "decode":
            verify = _kwarg_value(node, "verify")
            if verify is not None and _is_false(verify):
                self._add(
                    node,
                    "jwt_verify_disabled",
                    severity="critical",
                    message="JWT signature verification disabled — tokens can be forged",
                    call=call_label,
                )

            options = _kwarg_value(node, "options")
            if options is not None and _dict_has_false_verify(options):
                self._add(
                    node,
                    "jwt_verify_signature_disabled",
                    severity="critical",
                    message="verify_signature=False allows forged JWT tokens",
                    call=call_label,
                )

            algorithms = _kwarg_value(node, "algorithms")
            if algorithms is not None and _algorithm_is_none(algorithms):
                self._add(
                    node,
                    "jwt_algorithm_none",
                    severity="critical",
                    message='Algorithm "none" accepts unsigned tokens',
                    call=call_label,
                )

        if short == "encode":
            algorithm = _kwarg_value(node, "algorithm")
            if algorithm is not None and _algorithm_is_none(algorithm):
                self._add(
                    node,
                    "jwt_encode_algorithm_none",
                    severity="critical",
                    message='Encoding JWT with algorithm "none" produces unsigned tokens',
                    call=call_label,
                )

            key_arg = _kwarg_value(node, "key")
            if key_arg is None and len(node.args) >= 2:
                key_arg = node.args[1]
            if key_arg is not None and _is_string_constant(key_arg):
                value = key_arg.value  # type: ignore[attr-defined]
                if isinstance(value, str) and len(value) >= 8:
                    self._add(
                        node,
                        "hardcoded_jwt_secret",
                        severity="high",
                        message="Hardcoded JWT signing key — use environment variables or a secrets manager",
                        call=call_label,
                    )

            for kw in node.keywords:
                if kw.arg and _looks_like_secret_name(kw.arg) and _is_string_constant(kw.value):
                    self._add(
                        node,
                        "hardcoded_jwt_secret",
                        severity="high",
                        message="Hardcoded JWT signing secret in keyword argument",
                        call=call_label,
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            secret = node.value.value
            if len(secret) >= 16:
                for target in node.targets:
                    if isinstance(target, ast.Name) and _looks_like_secret_name(target.id):
                        self._add(
                            node,
                            "hardcoded_jwt_secret",
                            severity="high",
                            message=f"Hardcoded JWT secret assigned to {target.id}",
                        )
        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JSON Web Token handling in Python code.

  Flags disabled signature verification, algorithm ``none``, hardcoded
  signing keys, and unverified JWT header/claim access.
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
        """Return aggregate JWT security statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[JWTSecurityFinding]:
        """Return critical and high severity findings."""
        return [
            f
            for f in self.analyze()
            if f.severity in {"critical", "high"}
        ]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no JWT security issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        lines = [
            f"JWT security: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}, High: {high}",
            f"Health score: {self.health_score()}/100",
        ]
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
            lines.append("No JWT security issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
