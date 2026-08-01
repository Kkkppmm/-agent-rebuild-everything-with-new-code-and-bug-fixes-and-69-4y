"""InsecureTLSAnalyzer — detect disabled TLS certificate verification."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_CLIENTS = frozenset({"requests", "httpx", "urllib3", "aiohttp"})


@dataclass
class TLSFinding:
    """A disabled TLS verification pattern."""

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
class TLSStats:
    """Aggregate insecure-TLS analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _kwarg_is_false(node: ast.keyword) -> bool:
    return isinstance(node.value, ast.Constant) and node.value.value is False


class _TLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect disabled TLS verification."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TLSFinding] = []

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
            TLSFinding(
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

        # verify=False on HTTP client calls
        if isinstance(func, ast.Attribute):
            module = ""
            if isinstance(func.value, ast.Name):
                module = func.value.id
            elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
                module = func.value.value.id

            if module in _HTTP_CLIENTS or func.attr in ("get", "post", "put", "delete", "request"):
                for kw in node.keywords:
                    if kw.arg == "verify" and _kwarg_is_false(kw):
                        call_name = f"{module}.{func.attr}" if module else func.attr
                        self._add(
                            node,
                            call_name,
                            severity="critical",
                            message="TLS certificate verification disabled",
                            context="verify=False",
                        )

        # ssl._create_unverified_context()
        if isinstance(func, ast.Attribute):
            if func.attr == "_create_unverified_context":
                self._add(
                    node,
                    "ssl._create_unverified_context",
                    severity="critical",
                    message="Creates SSL context that skips certificate verification",
                )
            if func.attr == "CERT_NONE" and isinstance(func.value, ast.Name) and func.value.id == "ssl":
                self._add(
                    node,
                    "ssl.CERT_NONE",
                    severity="high",
                    message="Disables certificate validation in SSL context",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Attribute):
            if (
                node.value.attr == "CERT_NONE"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "ssl"
            ):
                self._add(
                    node,
                    "ssl.CERT_NONE",
                    severity="high",
                    message="Assigns disabled certificate validation to SSL context",
                )
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS certificate verification.

    Flags ``verify=False`` on HTTP clients, ``ssl._create_unverified_context``,
    and ``ssl.CERT_NONE`` usage.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TLSFinding] = []
        self._stats: TLSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[TLSFinding]:
        """Analyze the project and return insecure-TLS findings."""
        if self._findings:
            return self._findings

        findings: list[TLSFinding] = []
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
            visitor = _TLSVisitor(rel)
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

        self._stats = TLSStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TLSStats:
        """Return aggregate TLS security statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def critical(self) -> list[TLSFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS)."""
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
            f"Insecure TLS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing TLS findings."""
        self.analyze()
        lines = [
            "Insecure TLS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No disabled TLS verification found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
