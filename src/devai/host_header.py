"""HostHeaderAnalyzer — detect host header injection vulnerabilities."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_ATTRS = frozenset({"host", "hostname", "server_name", "HTTP_HOST"})
_WILDCARD_ALLOWED_HOSTS = re.compile(r"ALLOWED_HOSTS\s*=\s*\[.*\*.*\]", re.DOTALL)


@dataclass
class HostHeaderFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class HostHeaderStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _HostHeaderVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HostHeaderFinding] = []
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "ALLOWED_HOSTS":
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self.findings.append(
                                HostHeaderFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="wildcard_allowed_hosts",
                                    severity="high",
                                    message="ALLOWED_HOSTS = ['*'] accepts any Host header — enables cache poisoning",
                                    function=self._current_function(),
                                )
                            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"redirect", "url_for"} and node.args:
                for arg in node.args:
                    if self._uses_host_header(arg):
                        self.findings.append(
                            HostHeaderFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="host_in_redirect",
                                severity="high",
                                message=f"request.host used in {func.attr}() enables host header injection",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)

    def _uses_host_header(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute) and node.attr in _HOST_ATTRS:
            return True
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and str(node.slice.value).lower() in {"host", "http_host"}:
                return True
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and self._uses_host_header(v.value)
                for v in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._uses_host_header(node.left) or self._uses_host_header(node.right)
        if isinstance(node, ast.Attribute):
            return self._uses_host_header(node.value)
        return False

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        for val in node.values:
            if isinstance(val, ast.FormattedValue) and self._uses_host_header(val.value):
                self.findings.append(
                    HostHeaderFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="host_in_url",
                        severity="high",
                        message="request.host in URL construction enables host header injection",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class HostHeaderAnalyzer:
    """Detect host header injection vulnerabilities in web applications."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HostHeaderFinding] = []
        self._stats: HostHeaderStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[HostHeaderFinding]:
        findings: list[HostHeaderFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            if _WILDCARD_ALLOWED_HOSTS.search(line):
                findings.append(
                    HostHeaderFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="wildcard_allowed_hosts",
                        severity="high",
                        message="ALLOWED_HOSTS contains wildcard — accepts any Host header",
                    )
                )
            if "request.host" in line or "request.headers['Host']" in line:
                if any(kw in line for kw in ("redirect", "url", "http", "https", "f\"")):
                    findings.append(
                        HostHeaderFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="host_in_url",
                            severity="high",
                            message="request.host used in URL may enable host header injection",
                        )
                    )
        return findings

    def analyze(self) -> list[HostHeaderFinding]:
        if self._findings:
            return self._findings

        findings: list[HostHeaderFinding] = []
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
            visitor = _HostHeaderVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            all_findings = visitor.findings + line_findings
            if all_findings:
                files_with_findings.add(rel)
            findings.extend(all_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = HostHeaderStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HostHeaderStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 15.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Host header risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Host header analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No host header injection patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
