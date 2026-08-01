"""XXEAnalyzer — detect XML External Entity vulnerability patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_XML_MODULES = frozenset({"xml", "lxml", "xmltodict", "defusedxml"})
_XML_PARSE_ATTRS = frozenset({"parse", "fromstring", "iterparse", "XML", "XMLParser"})
_UNSAFE_PARSER_ATTRS = frozenset({"resolve_entities", "no_network", "load_dtd"})


@dataclass
class XXEFinding:
    """A potentially unsafe XML parsing pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class XXEStats:
    """Aggregate XXE analysis statistics."""

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


def _is_xml_call(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    attr = func.attr
    module = _module_name(func.value)
    if not module:
        return None

    base = module.split(".")[0]
    if base == "defusedxml":
        return None

    if base in _XML_MODULES or base == "xml":
        if attr in _XML_PARSE_ATTRS:
            return (
                "xml_unsafe_parse",
                "high",
                f"{module}.{attr}() may be vulnerable to XXE — use defusedxml or disable entity resolution",
            )
        if attr == "XMLParser":
            for kw in call.keywords:
                if kw.arg in _UNSAFE_PARSER_ATTRS:
                    val = kw.value
                    if isinstance(val, ast.Constant) and val.value is True and kw.arg == "resolve_entities":
                        return (
                            "xml_entity_resolution",
                            "critical",
                            "XMLParser with resolve_entities=True enables XXE attacks",
                        )
    return None


class _XXEVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XXE risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XXEFinding] = []
        self._function_stack: list[str] = []
        self._xml_aliases: set[str] = set()

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.startswith("defusedxml"):
                continue
            name = alias.asname or alias.name
            if alias.name.split(".")[0] == "xml" or alias.name in _XML_MODULES:
                self._xml_aliases.add(name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.startswith("defusedxml"):
            return
        if node.module and (node.module.split(".")[0] == "xml" or node.module in _XML_MODULES):
            for alias in node.names:
                name = alias.asname or alias.name
                self._xml_aliases.add(name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        result = _is_xml_call(node)
        if not result:
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in self._xml_aliases and func.attr in _XML_PARSE_ATTRS:
                    result = (
                        "xml_unsafe_parse",
                        "high",
                        f"{func.value.id}.{func.attr}() may be vulnerable to XXE — use defusedxml or disable entity resolution",
                    )
        if result:
            pattern, severity, message = result
            self.findings.append(
                XXEFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class XXEAnalyzer:
    """Detect XML External Entity (XXE) vulnerability patterns.

    Flags unsafe XML parsing with xml.etree, lxml, and xmltodict
    that may allow external entity resolution and file disclosure.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
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
        """Analyze the project and return XXE findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XXE risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = critical * 30.0 + high * 20.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"XXE: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing XXE findings."""
        self.analyze()
        lines = [
            "XXE analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No XXE vulnerability patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
