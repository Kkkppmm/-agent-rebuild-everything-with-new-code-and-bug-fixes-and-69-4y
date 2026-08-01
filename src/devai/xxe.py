"""XXEAnalyzer — detect XML External Entity (XXE) vulnerabilities in XML parsing."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|xml|data|body|content|payload|file|source|text|"
    r"stream|upload|response|raw|doc|document|path)",
    re.IGNORECASE,
)

_UNSAFE_XML_CALLS: dict[str, tuple[str, str, str]] = {
    "ET.parse": ("unsafe_etree_parse", "high", "ElementTree.parse() is vulnerable to XXE without defusedxml"),
    "ElementTree.parse": ("unsafe_etree_parse", "high", "ElementTree.parse() is vulnerable to XXE without defusedxml"),
    "ET.fromstring": ("unsafe_etree_fromstring", "high", "ElementTree.fromstring() is vulnerable to XXE without defusedxml"),
    "ElementTree.fromstring": ("unsafe_etree_fromstring", "high", "ElementTree.fromstring() is vulnerable to XXE without defusedxml"),
    "ET.iterparse": ("unsafe_etree_iterparse", "high", "ElementTree.iterparse() is vulnerable to XXE without defusedxml"),
    "ElementTree.iterparse": ("unsafe_etree_iterparse", "high", "ElementTree.iterparse() is vulnerable to XXE without defusedxml"),
    "minidom.parse": ("unsafe_minidom_parse", "high", "minidom.parse() is vulnerable to XXE without defusedxml"),
    "minidom.parseString": ("unsafe_minidom_parse_string", "high", "minidom.parseString() is vulnerable to XXE without defusedxml"),
    "xml.dom.minidom.parse": ("unsafe_minidom_parse", "high", "minidom.parse() is vulnerable to XXE without defusedxml"),
    "xml.dom.minidom.parseString": ("unsafe_minidom_parse_string", "high", "minidom.parseString() is vulnerable to XXE without defusedxml"),
    "sax.parse": ("unsafe_sax_parse", "high", "xml.sax.parse() is vulnerable to XXE without defusedxml"),
    "xml.sax.parse": ("unsafe_sax_parse", "high", "xml.sax.parse() is vulnerable to XXE without defusedxml"),
    "etree.parse": ("unsafe_lxml_parse", "critical", "lxml.etree.parse() is vulnerable to XXE — use defusedxml.lxml"),
    "etree.fromstring": ("unsafe_lxml_fromstring", "critical", "lxml.etree.fromstring() is vulnerable to XXE — use defusedxml.lxml"),
    "etree.XML": ("unsafe_lxml_xml", "critical", "lxml.etree.XML() is vulnerable to XXE — use defusedxml.lxml"),
    "pulldom.parse": ("unsafe_pulldom_parse", "high", "xml.dom.pulldom.parse() is vulnerable to XXE without defusedxml"),
    "xml.dom.pulldom.parse": ("unsafe_pulldom_parse", "high", "xml.dom.pulldom.parse() is vulnerable to XXE without defusedxml"),
}

_SAFE_DEFUSED_CALLS = frozenset({
    "defusedxml.ElementTree.parse",
    "defusedxml.ElementTree.fromstring",
    "defusedxml.ElementTree.iterparse",
    "defusedxml.minidom.parse",
    "defusedxml.minidom.parseString",
    "defusedxml.lxml.fromstring",
    "defusedxml.lxml.parse",
    "defusedxml.defuse_stdlib",
})


@dataclass
class XXEFinding:
    """An unsafe XML parsing pattern vulnerable to XXE."""

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


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _looks_like_user_input(node.func)
    return False


def _first_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in {"source", "file", "data", "string"}:
            return kw.value
    return None


def _is_unsafe_xml_call(name: str) -> tuple[str, str, str] | None:
    if name in _SAFE_DEFUSED_CALLS:
        return None
    if name in _UNSAFE_XML_CALLS:
        return _UNSAFE_XML_CALLS[name]
    for suffix, info in _UNSAFE_XML_CALLS.items():
        if name.endswith(suffix):
            return info
    return None


class _XXEVisitor(ast.NodeVisitor):
    """Walk a module AST and collect unsafe XML parsing patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[XXEFinding] = []
        self._function_stack: list[str] = []
        self._uses_defusedxml = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        severity: str,
        message: str,
        *,
        call: str = "",
    ) -> None:
        self.findings.append(
            XXEFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=call,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.startswith("defusedxml"):
                self._uses_defusedxml = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.startswith("defusedxml"):
            self._uses_defusedxml = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        info = _is_unsafe_xml_call(name)
        if info and not self._uses_defusedxml:
            pattern, severity, message = info
            first = _first_arg(node)
            if first is None or _looks_like_user_input(first):
                self._add(node, pattern, severity, message, call=name)
        self.generic_visit(node)


class XXEAnalyzer:
    """Detect XML External Entity (XXE) vulnerabilities in Python projects.

    Flags unsafe stdlib and lxml XML parsing when input may be user-controlled
    and defusedxml is not imported in the module.
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

    def critical_findings(self) -> list[XXEFinding]:
        """Return only critical-severity findings."""
        return [f for f in self.analyze() if f.severity == "critical"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XXE risks)."""
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
        lines = ["XXE analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unsafe XML parsing patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
