"""XXEAnalyzer — detect unsafe XML parsing vulnerable to external entity attacks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_XML_PARSE_ATTRS = frozenset(
    {
        "parse",
        "fromstring",
        "XML",
        "fromstring",
        "parseString",
        "parsestring",
    }
)
_XML_MODULES = frozenset(
    {
        "xml.etree.ElementTree",
        "ElementTree",
        "xml.dom.minidom",
        "minidom",
        "lxml.etree",
        "etree",
    }
)


@dataclass
class XXEFinding:
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
class XXEStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _module_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _is_xml_parse_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _XML_PARSE_ATTRS:
        base = _module_name(func.value)
        if base and any(mod in base for mod in ("ElementTree", "minidom", "etree", "xml")):
            return True
    if isinstance(func, ast.Name) and func.id in {"parse", "fromstring", "XML"}:
        return True
    return False


def _has_safe_parser_config(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg in {"resolve_entities", "no_network", "huge_tree"}:
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        if kw.arg == "parser" and isinstance(kw.value, ast.Call):
            return True
    return False


class _XXEVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XXEFinding] = []
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

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.startswith("xml.") and "defusedxml" not in alias.name:
                self.findings.append(
                    XXEFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unsafe_xml_import",
                        severity="medium",
                        message="Standard XML library imported — use defusedxml for untrusted input",
                        function=self._current_function(),
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.startswith("xml.") and "defusedxml" not in node.module:
            self.findings.append(
                XXEFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="unsafe_xml_import",
                    severity="medium",
                    message=f"Import from {node.module} — use defusedxml for untrusted input",
                    function=self._current_function(),
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        if _is_xml_parse_call(node) and not _has_safe_parser_config(node):
            self.findings.append(
                XXEFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="unsafe_xml_parse",
                    severity="high",
                    message="XML parsed without disabling external entities — XXE risk",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class XXEAnalyzer:
    """Detect XML parsing patterns vulnerable to XXE (XML External Entity) attacks."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[XXEFinding] = []
        self._stats: XXEStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[XXEFinding]:
        if self._findings:
            return self._findings

        findings: list[XXEFinding] = []
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
            visitor = _XXEVisitor(rel)
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
        self._stats = XXEStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> XXEStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"XXE risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["XXE analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No XXE-vulnerable XML parsing found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
