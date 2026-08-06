"""InsecureDotenvAnalyzer — detect load_dotenv(override=True) and unsafe dotenv usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_DOTENV_FUNCS = frozenset({"load_dotenv", "dotenv_values"})
_OVERRIDE_TRUE = re.compile(r"load_dotenv\s*\([^)]*override\s*=\s*True")


@dataclass
class InsecureDotenvFinding:
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
class InsecureDotenvStats:
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


def _has_override_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "override" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


class _InsecureDotenvVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureDotenvFinding] = []
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
        name = _call_name(node)
        if name in _DOTENV_FUNCS and _has_override_true(node):
            self.findings.append(
                InsecureDotenvFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="dotenv_override_true",
                    severity="high",
                    message=(
                        "load_dotenv(override=True) can overwrite production environment "
                        "variables with values from .env files"
                    ),
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class InsecureDotenvAnalyzer:
    """Detect python-dotenv usage that overrides existing environment variables."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureDotenvFinding] = []
        self._stats: InsecureDotenvStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureDotenvFinding]:
        findings: list[InsecureDotenvFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureDotenvVisitor(rel)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _OVERRIDE_TRUE.search(line):
                findings.append(
                    InsecureDotenvFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="dotenv_override_true",
                        severity="high",
                        message=(
                            "load_dotenv(override=True) can overwrite production "
                            "environment variables with values from .env files"
                        ),
                    )
                )
        return findings

    def analyze(self) -> list[InsecureDotenvFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureDotenvFinding] = []
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
        self._stats = InsecureDotenvStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureDotenvStats:
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
            f"Insecure dotenv risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure dotenv analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure dotenv patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
