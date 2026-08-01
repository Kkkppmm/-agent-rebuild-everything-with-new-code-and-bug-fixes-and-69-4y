"""UnsafeDeserializationAnalyzer — detect unsafe pickle, yaml, and marshal usage."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNSAFE_CALLS: dict[tuple[str, str], tuple[str, str]] = {
    ("pickle", "loads"): ("high", "pickle.loads can execute arbitrary code"),
    ("pickle", "load"): ("high", "pickle.load can execute arbitrary code"),
    ("marshal", "loads"): ("high", "marshal.loads is not safe for untrusted data"),
    ("marshal", "load"): ("high", "marshal.load is not safe for untrusted data"),
}


@dataclass
class DeserializationFinding:
    """An unsafe deserialization call."""

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
class DeserializationStats:
    """Aggregate unsafe-deserialization analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_module_attr(node: ast.Call) -> tuple[str, str] | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None


def _yaml_load_is_unsafe(node: ast.Call) -> bool:
    mod_attr = _call_module_attr(node)
    if mod_attr != ("yaml", "load"):
        return False
    for kw in node.keywords:
        if kw.arg == "Loader":
            if isinstance(kw.value, ast.Attribute):
                attr = kw.value.attr
                if attr in ("SafeLoader", "CSafeLoader"):
                    return False
            if isinstance(kw.value, ast.Name) and kw.value.id in ("SafeLoader", "CSafeLoader"):
                return False
    # No safe Loader specified — unsafe by default in PyYAML
    return True


class _DeserializationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe deserialization calls."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[DeserializationFinding] = []

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
            DeserializationFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                name=name,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        mod_attr = _call_module_attr(node)
        if mod_attr and mod_attr in _UNSAFE_CALLS:
            severity, message = _UNSAFE_CALLS[mod_attr]
            self._add(
                node,
                f"{mod_attr[0]}.{mod_attr[1]}",
                severity=severity,
                message=message,
            )
        elif _yaml_load_is_unsafe(node):
            self._add(
                node,
                "yaml.load",
                severity="high",
                message="Use yaml.safe_load or Loader=yaml.SafeLoader for untrusted input",
            )
        self.generic_visit(node)


class UnsafeDeserializationAnalyzer:
    """Detect unsafe deserialization via pickle, yaml.load, and marshal.

    Flags ``pickle.loads``, ``pickle.load``, ``marshal.loads``, and ``yaml.load``
    without a safe Loader.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[DeserializationFinding] = []
        self._stats: DeserializationStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[DeserializationFinding]:
        """Analyze the project and return unsafe-deserialization findings."""
        if self._findings:
            return self._findings

        findings: list[DeserializationFinding] = []
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
            visitor = _DeserializationVisitor(rel)
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

        self._stats = DeserializationStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> DeserializationStats:
        """Return aggregate deserialization statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[DeserializationFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no unsafe deserialization)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Unsafe deserialization: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing deserialization findings."""
        self.analyze()
        lines = [
            "Unsafe deserialization analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No unsafe deserialization calls found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
