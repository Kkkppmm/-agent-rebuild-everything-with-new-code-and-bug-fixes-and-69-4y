"""XXEAnalyzer — detect XML External Entity vulnerabilities in XML parsers."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|xml|data|payload|body|content|document|source|text|"
    r"param|query|upload|file|stream|bytes|raw)",
    re.IGNORECASE,
)

_XML_MODULES = frozenset({"xml", "lxml", "ET", "ElementTree", "etree"})
_XML_PARSE_FUNCS = frozenset(
    {
        "parse",
        "fromstring",
        "fromstringlist",
        "iterparse",
        "XML",
        "XMLParser",
    }
)


@dataclass
class XXEFinding:
    """A potentially unsafe XML parsing pattern."""

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


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _looks_like_user_input(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _looks_like_user_input(node.left) or _looks_like_user_input(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return any(_looks_like_user_input(arg) for arg in node.args) or any(
                _looks_like_user_input(kw.value) for kw in node.keywords
            )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _looks_like_user_input(node.right)
    return _looks_like_user_input(node)


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


def _first_xml_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in {"source", "data", "file", "text"}:
            return kw.value
    return None


def _has_external_entities_enabled(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg in {"resolve_entities", "no_network"}:
            if isinstance(kw.value, ast.Constant):
                if kw.arg == "resolve_entities" and kw.value.value is True:
                    return True
                if kw.arg == "no_network" and kw.value.value is False:
                    return True
    return False


_XML_MODULES = frozenset({"xml", "lxml", "ET", "ElementTree", "etree"})


def _is_xxe_call(node: ast.Call) -> tuple[str, str, str] | None:
    """Return (pattern, severity, message) for risky XML parsing."""
    name = _call_name(node)
    parts = name.split(".")
    module = parts[0] if parts else ""
    method = parts[-1] if parts else ""
    xml_arg = _first_xml_arg(node)

    if module == "defusedxml" or name.startswith("defusedxml."):
        return None

    if method not in _XML_PARSE_FUNCS:
        return None

    if module in _XML_MODULES or module == "xml":
        if xml_arg and _is_dynamic_string(xml_arg):
            pattern = "dynamic_lxml_xml" if module == "lxml" else "dynamic_stdlib_xml"
            message = (
                "lxml parser called with user-controlled input — use defusedxml or disable entities"
                if module == "lxml"
                else "stdlib XML parser called with user-controlled input — disable external entities"
            )
            return pattern, "high", message
        if _has_external_entities_enabled(node):
            return (
                "enabled_external_entities",
                "high",
                "XML parser configured to resolve external entities",
            )

    return None


class _XXEVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XXE risks."""

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

    def visit_Call(self, node: ast.Call) -> None:
        result = _is_xxe_call(node)
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
    """Detect XML External Entity (XXE) risks in Python projects.

    Flags stdlib ``xml.etree`` and ``lxml`` parsers called with user-controlled
    input or configured to resolve external entities.
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
            lines.append("No unsafe XML parsing patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
