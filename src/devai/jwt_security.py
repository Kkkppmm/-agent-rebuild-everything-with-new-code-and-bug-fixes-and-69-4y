"""JWTSecurityAnalyzer — detect insecure JWT handling."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class JWTFinding:
    """An insecure JWT decode or verification pattern."""

    path: str
    lineno: int
    name: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.name}{ctx}: "
            f"{self.message}"
        )


@dataclass
class JWTStats:
    """Aggregate JWT security analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _kwarg_is_false(node: ast.keyword) -> bool:
    return isinstance(node.value, ast.Constant) and node.value.value is False


def _contains_none_algorithm(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "none":
        return True
    if isinstance(node, ast.List):
        return any(
            isinstance(elt, ast.Constant) and str(elt.value).lower() == "none"
            for elt in node.elts
        )
    return False


class _JWTVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure JWT patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[JWTFinding] = []

    def _add(
        self,
        node: ast.AST,
        name: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            JWTFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                name=name,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        is_jwt_decode = False
        call_name = ""

        if isinstance(func, ast.Attribute):
            if func.attr == "decode" and isinstance(func.value, ast.Name):
                if func.value.id in ("jwt", "jose_jwt"):
                    is_jwt_decode = True
                    call_name = f"{func.value.id}.decode"
            elif func.attr == "decode" and isinstance(func.value, ast.Attribute):
                if (
                    isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "jwt"
                    and func.value.attr == "api_jwt"
                ):
                    is_jwt_decode = True
                    call_name = "jwt.api_jwt.decode"

        if is_jwt_decode:
            for kw in node.keywords:
                if kw.arg == "verify" and _kwarg_is_false(kw):
                    self._add(
                        node,
                        call_name,
                        severity="critical",
                        message="JWT signature verification disabled",
                        context="verify=False",
                    )
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for key, val in zip(kw.value.keys, kw.value.values, strict=False):
                        if (
                            isinstance(key, ast.Constant)
                            and key.value == "verify_signature"
                            and isinstance(val, ast.Constant)
                            and val.value is False
                        ):
                            self._add(
                                node,
                                call_name,
                                severity="critical",
                                message="JWT signature verification disabled via options",
                                context="verify_signature=False",
                            )
                if kw.arg == "algorithms" and _contains_none_algorithm(kw.value):
                    self._add(
                        node,
                        call_name,
                        severity="critical",
                        message="JWT algorithm 'none' allows unsigned tokens",
                        context="algorithms includes none",
                    )

        self.generic_visit(node)


class JWTSecurityAnalyzer:
    """Detect insecure JWT decode and verification patterns.

    Flags ``jwt.decode`` calls with ``verify=False``, ``verify_signature=False``,
    or ``algorithms`` containing ``none``.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[JWTFinding] = []
        self._stats: JWTStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[JWTFinding]:
        """Analyze the project and return JWT security findings."""
        if self._findings:
            return self._findings

        findings: list[JWTFinding] = []
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
            visitor = _JWTVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = JWTStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> JWTStats:
        """Return aggregate JWT security statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def critical(self) -> list[JWTFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure JWT handling)."""
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
        critical = stats.by_severity.get("critical", 0)
        lines = [
            f"JWT security: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}",
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
            lines.append("No insecure JWT handling found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
