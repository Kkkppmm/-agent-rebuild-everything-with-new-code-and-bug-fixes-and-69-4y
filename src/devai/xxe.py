"""XXEAnalyzer — detect XML External Entity vulnerabilities in XML parsers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNSAFE_PARSE_FUNCS = frozenset({"parse", "fromstring", "parseString", "XML"})
_SAFE_MODULES = frozenset({"defusedxml", "defusedxml.ElementTree", "defusedxml.lxml"})
_RISKY_MODULES = frozenset(
    {
        "xml.etree.ElementTree",
        "ElementTree",
        "ET",
        "xml.dom.minidom",
        "minidom",
        "lxml.etree",
        "xml.sax",
    }
)


@dataclass
class XXEFinding:
    """A potentially unsafe XML parsing call vulnerable to XXE."""

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


def _call_qualname(node: ast.Call) -> str:
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


def _is_safe_module(qualname: str) -> bool:
    return any(qualname.startswith(safe) for safe in _SAFE_MODULES)


def _resolve_call_target(node: ast.Call, aliases: dict[str, str]) -> str:
    """Resolve a call to its fully-qualified module path using import aliases."""
    func = node.func
    if isinstance(func, ast.Attribute):
        base_name = ""
        if isinstance(func.value, ast.Name):
            base_name = func.value.id
        elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            base_name = f"{func.value.value.id}.{func.value.attr}"
        resolved_base = aliases.get(base_name, base_name)
        if resolved_base:
            return f"{resolved_base}.{func.attr}"
        return _call_qualname(node)
    if isinstance(func, ast.Name):
        resolved = aliases.get(func.id, func.id)
        return resolved
    return _call_qualname(node)


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names to their fully-qualified module paths."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[-1]
                aliases[name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                name = alias.asname or alias.name
                aliases[name] = f"{node.module}.{alias.name}"
    return aliases


def _is_risky_parser_call(qualname: str, attr: str) -> tuple[str, str, str] | None:
    if attr not in _UNSAFE_PARSE_FUNCS:
        return None
    if _is_safe_module(qualname):
        return None

    short = qualname.split(".")[-2:] if "." in qualname else [qualname]
    label = ".".join(short) if len(short) > 1 else qualname

    if qualname.endswith("ElementTree.parse") or qualname.endswith("ET.parse"):
        return (
            "etree_parse",
            "high",
            "xml.etree.ElementTree.parse() is vulnerable to XXE — use defusedxml",
        )
    if qualname.endswith("ElementTree.fromstring") or qualname.endswith("ET.fromstring"):
        return (
            "etree_fromstring",
            "high",
            "xml.etree.ElementTree.fromstring() is vulnerable to XXE — use defusedxml",
        )
    if qualname.endswith("ElementTree.XML") or qualname.endswith("ET.XML"):
        return (
            "etree_xml",
            "high",
            "xml.etree.ElementTree.XML() is vulnerable to XXE — use defusedxml",
        )
    if "minidom" in qualname and attr in {"parse", "parseString"}:
        return (
            f"minidom_{attr}",
            "high",
            f"xml.dom.minidom.{attr}() is vulnerable to XXE — use defusedxml",
        )
    if qualname.endswith("etree.parse") or qualname.endswith("etree.fromstring"):
        return (
            f"lxml_{attr}",
            "high",
            f"lxml.etree.{attr}() may be vulnerable to XXE — disable entity resolution",
        )
    if "xml.sax" in qualname and attr == "parse":
        return (
            "sax_parse",
            "medium",
            "xml.sax.parse() may resolve external entities — use a hardened parser",
        )
    if label in _RISKY_MODULES or any(part in qualname for part in ("ElementTree", "minidom", "lxml")):
        return (
            f"xml_{attr}",
            "medium",
            f"XML {attr}() call may be vulnerable to XXE — prefer defusedxml",
        )
    return None


def _classify_xml_parser_ctor(node: ast.Call, aliases: dict[str, str] | None = None) -> tuple[str, str, str] | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "XMLParser":
        return None
    qualname = _resolve_call_target(node, aliases or {})
    if _is_safe_module(qualname):
        return None
    if "ElementTree" not in qualname and not qualname.endswith("XMLParser"):
        return None

    for keyword in node.keywords:
        if keyword.arg == "resolve_entities" and isinstance(keyword.value, ast.Constant):
            if keyword.value.value is False:
                return None

    return (
        "unsafe_xml_parser",
        "medium",
        "XMLParser created without resolve_entities=False — may allow external entities",
    )


class _XXEVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XXE risks."""

    def __init__(self, path: str, aliases: dict[str, str]) -> None:
        self.path = path
        self.aliases = aliases
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
        qualname = _resolve_call_target(node, self.aliases)
        attr = qualname.rsplit(".", 1)[-1] if qualname else ""

        result = _is_risky_parser_call(qualname, attr)
        if result is None:
            result = _classify_xml_parser_ctor(node, self.aliases)

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
    """Detect XML External Entity (XXE) vulnerabilities in Python XML parsers.

    Flags unsafe uses of stdlib ``xml.etree.ElementTree``, ``xml.dom.minidom``,
    ``xml.sax``, and ``lxml.etree`` parsing APIs that may resolve external entities.
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
            aliases = _collect_import_aliases(tree)
            visitor = _XXEVisitor(rel, aliases)
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
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
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
