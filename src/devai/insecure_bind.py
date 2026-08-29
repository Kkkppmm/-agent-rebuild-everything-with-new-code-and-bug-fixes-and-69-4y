"""InsecureBindAnalyzer — detect services bound to all interfaces (0.0.0.0)."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_BIND_ALL = re.compile(r"""['"]0\.0\.0\.0['"]|['"]\*['"]|['"]::['"]""")
_HOST_ALL = re.compile(r"""host\s*=\s*['"](?:0\.0\.0\.0|\*|::)['"]""")
_BIND_CALL = re.compile(r"""\.bind\s*\(\s*\(\s*['"](?:0\.0\.0\.0|\*|::)['"]""")


@dataclass
class InsecureBindFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    value: str = ""

    def format(self) -> str:
        detail = f" ({self.value})" if self.value else ""
        return f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{detail}: {self.message}"


@dataclass
class InsecureBindStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_all_interfaces(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value in ("0.0.0.0", "*", "::")
    return False


class _InsecureBindVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureBindFinding] = []

    def _add(self, lineno: int, pattern: str, severity: str, message: str, value: str = "") -> None:
        self.findings.append(
            InsecureBindFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                value=value,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "bind" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Tuple) and first.elts:
                    if _is_all_interfaces(first.elts[0]):
                        val = getattr(first.elts[0], "value", "0.0.0.0")
                        self._add(
                            node.lineno,
                            "bind_all_interfaces",
                            "high",
                            "Binding to all interfaces exposes the service on every network",
                            str(val),
                        )
                elif _is_all_interfaces(first):
                    val = getattr(first, "value", "0.0.0.0")
                    self._add(
                        node.lineno,
                        "bind_all_interfaces",
                        "high",
                        "Binding to all interfaces exposes the service on every network",
                        str(val),
                    )

            if func.attr in ("run", "serve", "listen") and isinstance(func.value, ast.Name):
                for kw in node.keywords:
                    if kw.arg == "host" and _is_all_interfaces(kw.value):
                        val = getattr(kw.value, "value", "0.0.0.0")
                        self._add(
                            node.lineno,
                            "host_all_interfaces",
                            "high",
                            f"{func.value.id}.{func.attr}() with host bound to all interfaces",
                            str(val),
                        )
        self.generic_visit(node)


class InsecureBindAnalyzer:
    """Detect network services bound to 0.0.0.0 or all interfaces."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureBindFinding] = []
        self._stats: InsecureBindStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureBindFinding]:
        findings: list[InsecureBindFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureBindVisitor(rel)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HOST_ALL.search(line) or _BIND_CALL.search(line):
                match = _BIND_ALL.search(line)
                val = match.group(0).strip("'\"") if match else "0.0.0.0"
                findings.append(
                    InsecureBindFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="host_all_interfaces",
                        severity="high",
                        message="Service configured to listen on all network interfaces",
                        value=val,
                    )
                )
        return findings

    def analyze(self) -> list[InsecureBindFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureBindFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureBindStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureBindStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure bind risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure bind analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure bind patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
