"""WildcardHostsAnalyzer — detect permissive ALLOWED_HOSTS and trusted-origin settings."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_SETTING_NAMES = frozenset(
    {
        "ALLOWED_HOSTS",
        "TRUSTED_ORIGINS",
        "CSRF_TRUSTED_ORIGINS",
        "ALLOWED_ORIGINS",
    }
)


@dataclass
class WildcardHostsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        setting = f" ({self.setting})" if self.setting else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{setting}: {self.message}"


@dataclass
class WildcardHostsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _contains_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(
            isinstance(elt, ast.Constant) and elt.value == "*" for elt in node.elts
        )
    return False


def _setting_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name) and target.id in _HOST_SETTING_NAMES:
        return target.id
    if isinstance(target, ast.Attribute) and target.attr in _HOST_SETTING_NAMES:
        return target.attr
    return None


def _is_environ_setdefault(node: ast.Call) -> tuple[str, ast.AST] | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "setdefault":
        return None
    base = func.value
    if isinstance(base, ast.Attribute) and base.attr == "environ":
        if isinstance(base.value, ast.Name) and base.value.id == "os":
            pass
        else:
            return None
    elif isinstance(base, ast.Name) and base.id == "environ":
        pass
    else:
        return None
    if (
        len(node.args) >= 2
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value in _HOST_SETTING_NAMES
    ):
        return node.args[0].value, node.args[1]
    return None


class _WildcardHostsVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WildcardHostsFinding] = []
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

    def _add_wildcard_finding(self, node: ast.AST, setting: str) -> None:
        self.findings.append(
            WildcardHostsFinding(
                path=self.path,
                lineno=node.lineno,
                pattern="wildcard_host_setting",
                severity="high",
                message=(
                    f"{setting} includes '*' — restrict to explicit hostnames "
                    "to prevent host header attacks"
                ),
                setting=setting,
                function=self._current_function(),
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            setting = _setting_name(target)
            if setting and _contains_wildcard(node.value):
                self._add_wildcard_finding(node, setting)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            setting = _setting_name(node.target)
            if setting and _contains_wildcard(node.value):
                self._add_wildcard_finding(node, setting)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        match = _is_environ_setdefault(node)
        if match and _contains_wildcard(match[1]):
            self._add_wildcard_finding(node, match[0])
        self.generic_visit(node)


class WildcardHostsAnalyzer:
    """Detect permissive ALLOWED_HOSTS and trusted-origin configuration."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[WildcardHostsFinding] = []
        self._stats: WildcardHostsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[WildcardHostsFinding]:
        if self._findings:
            return self._findings

        findings: list[WildcardHostsFinding] = []
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
            visitor = _WildcardHostsVisitor(rel)
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
        self._stats = WildcardHostsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> WildcardHostsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 30.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Wildcard host settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Wildcard hosts analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No permissive host settings found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
