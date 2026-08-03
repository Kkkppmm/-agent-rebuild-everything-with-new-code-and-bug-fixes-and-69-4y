"""CORSAnalyzer — detect overly permissive Cross-Origin Resource Sharing settings."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class CORSFinding:
    """An overly permissive CORS configuration."""

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
            f"{self.path}:{self.lineno}{call} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class CORSStats:
    """Aggregate CORS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List):
        return any(_is_wildcard(elt) for elt in node.elts)
    return False


def _kw_bool(node: ast.keyword) -> bool | None:
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
        return node.value.value
    return None


class _CORSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect permissive CORS configurations."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CORSFinding] = []

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
            CORSFinding(
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

        if name == "CORS":
            wildcard_origin = False
            credentials = False
            for kw in node.keywords:
                if kw.arg in {"origins", "resources", "allow_origins"} and _is_wildcard(kw.value):
                    wildcard_origin = True
                if kw.arg in {"supports_credentials", "allow_credentials"} and _kw_bool(kw) is True:
                    credentials = True
            for arg in node.args:
                if _is_wildcard(arg):
                    wildcard_origin = True
            if wildcard_origin and credentials:
                self._add(
                    node,
                    "cors_wildcard_with_credentials",
                    severity="high",
                    message="Wildcard origin with credentials allows any site to make authenticated requests",
                    call="CORS",
                )
            elif wildcard_origin:
                self._add(
                    node,
                    "cors_wildcard_origin",
                    severity="medium",
                    message='Wildcard CORS origin "*" allows any domain to access this API',
                    call="CORS",
                )

        if name == "CORSMiddleware":
            wildcard_origin = False
            credentials = False
            for kw in node.keywords:
                if kw.arg == "allow_origins" and _is_wildcard(kw.value):
                    wildcard_origin = True
                if kw.arg == "allow_credentials" and _kw_bool(kw) is True:
                    credentials = True
            if wildcard_origin and credentials:
                self._add(
                    node,
                    "cors_wildcard_with_credentials",
                    severity="high",
                    message="allow_origins=['*'] with allow_credentials=True is invalid and insecure",
                    call="CORSMiddleware",
                )
            elif wildcard_origin:
                self._add(
                    node,
                    "cors_wildcard_origin",
                    severity="medium",
                    message='allow_origins=["*"] permits cross-origin access from any domain',
                    call="CORSMiddleware",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name) and re.search(
                    r"(cors|origin|access.control)", target.id, re.IGNORECASE
                ):
                    if value == "*":
                        self._add(
                            node,
                            "cors_header_wildcard",
                            severity="medium",
                            message=f'Header {target.id} set to "*" allows any origin',
                            call=target.id,
                        )
        self.generic_visit(node)


class CORSAnalyzer:
    """Detect overly permissive CORS configurations in web applications.

    Flags wildcard origins, wildcard origins combined with credentials,
    and permissive CORS header assignments in Flask, FastAPI, and similar apps.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CORSFinding] = []
        self._stats: CORSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[CORSFinding]:
        """Analyze the project and return CORS misconfiguration findings."""
        if self._findings:
            return self._findings

        findings: list[CORSFinding] = []
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
            visitor = _CORSVisitor(rel)
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
        self._stats = CORSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CORSStats:
        """Return aggregate CORS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CORSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CORS misconfigurations)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 12.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"CORS misconfigurations: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing CORS findings."""
        self.analyze()
        lines = ["CORS analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No CORS misconfigurations found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
