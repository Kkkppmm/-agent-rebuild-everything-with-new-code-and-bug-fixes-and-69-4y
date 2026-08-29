"""InsecureFileUploadAnalyzer — detect file upload handlers without validation."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UPLOAD_ATTRS = frozenset({"files", "file", "upload", "UPLOAD"})
_VALIDATION_ATTRS = frozenset(
    {
        "content_type",
        "filename",
        "endswith",
        "allowed_extensions",
        "validate",
        "check",
        "secure_filename",
        "getsize",
        "size",
    }
)


@dataclass
class InsecureFileUploadFinding:
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
class InsecureFileUploadStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_upload_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _UPLOAD_ATTRS:
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
    return False


class _InsecureFileUploadVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureFileUploadFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def _check_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        has_upload = False
        has_validation = False

        for child in ast.walk(node):
            if _is_upload_access(child):
                has_upload = True
            if isinstance(child, ast.Attribute) and child.attr in _VALIDATION_ATTRS:
                has_validation = True
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name) and func.id == "secure_filename":
                    has_validation = True
                if isinstance(func, ast.Attribute) and func.attr in _VALIDATION_ATTRS:
                    has_validation = True

        if has_upload and not has_validation:
            self.findings.append(
                InsecureFileUploadFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="unvalidated_upload",
                    severity="high",
                    message=f"Handler '{node.name}' processes uploads without type or size validation",
                    function=node.name,
                )
            )


class InsecureFileUploadAnalyzer:
    """Detect file upload handlers missing content-type, extension, or size checks."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureFileUploadFinding] = []
        self._stats: InsecureFileUploadStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureFileUploadFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureFileUploadFinding] = []
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
            visitor = _InsecureFileUploadVisitor(rel)
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
        self._stats = InsecureFileUploadStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureFileUploadStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure file upload risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure file upload analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure file upload risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
