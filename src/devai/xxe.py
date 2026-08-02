"""XXEAnalyzer — detect XML external entity injection risks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_XML_PARSE_ATTRS = frozenset({"parse", "fromstring", "parseString", "read"})
_XML_MODULES = frozenset(
    {
        "xml.etree.ElementTree",
        "ElementTree",
        "xml.dom.minidom",
        "minidom",
        "xml.sax",
        "lxml.etree",
        "etree",
    }
)
_DEFUSED_PREFIXES = frozenset({"defusedxml", "defused"})


@dataclass
class XXEFinding:
    """A potentially unsafe XML parsing call."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


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


def _is_defused_module(module: str) -> bool:
    return any(module.startswith(prefix) for prefix in _DEFUSED_PREFIXES)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _is_xml_parser_constructor(call: ast.Call) -> tuple[str, str, str] | None:
    """Detect XMLParser() without defusedxml and with entity resolution."""
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "XMLParser":
        return None
    module = _module_name(func.value) or ""
    if _is_defused_module(module):
        return None
    if "etree" in module or module in {"ElementTree", "lxml"}:
        return (
            "xml_parser_unsafe",
            "high",
            "XMLParser without defusedxml may resolve external entities — use defusedxml",
        )
    return None


def _classify_xxe_call(call: ast.Call, xml_aliases: set[str] = frozenset()) -> tuple[str, str, str] | None:
    name = _call_name(call)
    if not name:
        return None

    parts = name.split(".")
    attr = parts[-1]
    module = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]

    if _is_defused_module(module) or _is_defused_module(name):
        return None

    if attr in _XML_PARSE_ATTRS:
        if _is_defused_module(module) or _is_defused_module(name):
            return None
        for xml_mod in _XML_MODULES:
            if module == xml_mod or name.startswith(xml_mod) or module.endswith(xml_mod.split(".")[-1]):
                return (
                    f"{attr}_unsafe_xml",
                    "high",
                    f"{name}() may process external entities — use defusedxml or disable entity resolution",
                )
        # Common aliases after `import xml.etree.ElementTree as ET`
        if attr in {"parse", "fromstring", "parseString", "read"} and module in xml_aliases:
            return (
                f"{attr}_unsafe_xml",
                "high",
                f"{name}() may process external entities — use defusedxml or disable entity resolution",
            )

    if attr == "parse" and module in {"sax", "xml.sax"}:
        return (
            "sax_parse_unsafe",
            "high",
            "xml.sax.parse() may resolve external entities — use defusedxml.sax",
        )

    parser_result = _is_xml_parser_constructor(call)
    if parser_result:
        return parser_result

    return None


class _XXEVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XXE risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XXEFinding] = []
        self._function_stack: list[str] = []
        self._xml_aliases: set[str] = set()
        self._defused_aliases: set[str] = set()

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            if _is_defused_module(alias.name):
                self._defused_aliases.add(name.split(".")[0])
            elif any(tag in alias.name for tag in ("xml", "etree", "minidom", "sax", "lxml")):
                self._xml_aliases.add(name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            if _is_defused_module(module) or _is_defused_module(f"{module}.{alias.name}"):
                self._defused_aliases.add(name)
            elif any(tag in module for tag in ("xml", "etree", "minidom", "sax", "lxml")):
                self._xml_aliases.add(name)

    def _is_unsafe_xml_alias(self, module: str) -> bool:
        return module in self._xml_aliases and module not in self._defused_aliases

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_xxe_call(node, self._xml_aliases)
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
                    call=_call_name(node),
                )
            )
        self.generic_visit(node)


class XXEAnalyzer:
    """Detect XML external entity injection risks in Python projects.

    Flags xml.etree.ElementTree.parse, lxml.etree, xml.dom.minidom,
    and xml.sax calls that may resolve external entities from untrusted XML.
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

    def high_severity(self) -> list[XXEFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XXE risks)."""
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
            f"XXE risks: {stats.total_findings} findings in "
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
            lines.append("No XXE patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
