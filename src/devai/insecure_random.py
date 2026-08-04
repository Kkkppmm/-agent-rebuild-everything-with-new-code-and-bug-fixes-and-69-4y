"""InsecureRandomAnalyzer — detect cryptographically weak random usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_RE = re.compile(
    r"(token|password|passwd|secret|api[_-]?key|auth|salt|nonce|session|otp|pin|credential)",
    re.IGNORECASE,
)

_RANDOM_ATTRS = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "sample",
        "shuffle",
        "uniform",
        "getrandbits",
        "seed",
    }
)


@dataclass
class InsecureRandomFinding:
    """A potentially insecure use of the pseudo-random module."""

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
class InsecureRandomStats:
    """Aggregate insecure-random analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_RE.search(name))


def _random_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "random" and func.attr in _RANDOM_ATTRS:
            return f"random.{func.attr}"
    if isinstance(func, ast.Name) and func.id in _RANDOM_ATTRS:
        return func.id
    return None


def _assignment_target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Tuple):
        for elt in node.elts:
            names.extend(_assignment_target_names(elt))
    return names


class _InsecureRandomVisitor(ast.NodeVisitor):
    """Walk a module AST and collect weak random usage."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureRandomFinding] = []
        self._uses_random_import = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "random":
                self._uses_random_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "random":
            self._uses_random_import = True
        self.generic_visit(node)

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
            InsecureRandomFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                name=name,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call_name = _random_call_name(node.value)
            if call_name:
                for target in node.targets:
                    for var_name in _assignment_target_names(target):
                        if _is_sensitive_name(var_name):
                            self._add(
                                node,
                                call_name,
                                severity="high",
                                message="Use secrets module for security-sensitive values",
                                context=f"assigned to {var_name}",
                            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _random_call_name(node)
        if call_name:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    if arg.value >= 16:
                        self._add(
                            node,
                            call_name,
                            severity="medium",
                            message="Large random range via random module — prefer secrets for tokens",
                            context=f"range={arg.value}",
                        )
            for kw in node.keywords:
                if kw.arg and _is_sensitive_name(kw.arg):
                    self._add(
                        node,
                        call_name,
                        severity="high",
                        message="Use secrets module for security-sensitive parameters",
                        context=f"kwarg={kw.arg}",
                    )
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            call_name = _random_call_name(node.value)
            if call_name and call_name.endswith(".seed"):
                self._add(
                    node,
                    call_name,
                    severity="medium",
                    message="Seeding random module weakens unpredictability for security use",
                )
        self.generic_visit(node)


class InsecureRandomAnalyzer:
    """Detect use of ``random`` for security-sensitive values.

    Flags assignments to variables like ``token`` or ``password`` that use
    ``random.randint``, ``random.choice``, etc. Recommends the ``secrets``
  module for cryptographic randomness.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureRandomFinding] = []
        self._stats: InsecureRandomStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureRandomFinding]:
        """Analyze the project and return insecure-random findings."""
        if self._findings:
            return self._findings

        findings: list[InsecureRandomFinding] = []
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
            visitor = _InsecureRandomVisitor(rel)
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

        self._stats = InsecureRandomStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureRandomStats:
        """Return aggregate insecure-random statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureRandomFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure random usage)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Insecure random: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure-random findings."""
        self.analyze()
        lines = [
            "Insecure random analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure random usage found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
