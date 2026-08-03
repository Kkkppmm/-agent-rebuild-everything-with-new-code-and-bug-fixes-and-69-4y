"""TimingAttackAnalyzer — detect non-constant-time secret comparisons."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|signature|hash|digest|"
    r"auth|credential|hmac|checksum|key|nonce|salt|otp|pin)",
    re.IGNORECASE,
)

_SAFE_COMPARE_FUNCS = frozenset({
    "compare_digest",
    "safe_str_cmp",
    "timing_safe_equal",
    "constant_time_compare",
})


@dataclass
class TimingAttackFinding:
    """A non-constant-time comparison of secret values."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno}{ctx} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class TimingAttackStats:
    """Aggregate timing-attack analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_secret_name(name: str) -> bool:
    return bool(_SECRET_RE.search(name))


def _name_from_node(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class _TimingAttackVisitor(ast.NodeVisitor):
    """Walk a module AST and collect timing-attack risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TimingAttackFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            TimingAttackFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                left_name = _name_from_node(node.left)
                right_name = _name_from_node(comparator)
                if _is_secret_name(left_name) or _is_secret_name(right_name):
                    self._add(
                        node,
                        "insecure_secret_compare",
                        severity="high",
                        message="Use hmac.compare_digest() or secrets.compare_digest() for secret comparison",
                        context=f"{left_name} == {right_name}".strip(" ="),
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "verify":
            base = _name_from_node(func.value)
            if _is_secret_name(base):
                self._add(
                    node,
                    "verify_without_constant_time",
                    severity="medium",
                    message="Verify password/token comparison uses constant-time algorithm",
                    context=base,
                )
        self.generic_visit(node)


class TimingAttackAnalyzer:
    """Detect non-constant-time secret comparisons vulnerable to timing attacks.

    Flags ``==`` comparisons involving passwords, tokens, and signatures that
    should use ``hmac.compare_digest()`` or ``secrets.compare_digest()``.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TimingAttackFinding] = []
        self._stats: TimingAttackStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[TimingAttackFinding]:
        """Analyze the project and return timing-attack findings."""
        if self._findings:
            return self._findings

        findings: list[TimingAttackFinding] = []
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
            visitor = _TimingAttackVisitor(rel)
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
        self._stats = TimingAttackStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TimingAttackStats:
        """Return aggregate timing-attack statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[TimingAttackFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no timing-attack risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Timing attack risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing timing-attack findings."""
        self.analyze()
        lines = ["Timing attack analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No timing attack risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
