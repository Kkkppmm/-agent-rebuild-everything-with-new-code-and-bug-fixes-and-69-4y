"""InsecureFileUploadAnalyzer — detect unsafe file upload handling."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UPLOAD_ATTRS = frozenset({"files", "FILES", "file", "upload", "uploaded_file"})
_SAVE_ATTRS = frozenset({"save", "write", "writelines"})
_SECURE_FUNCS = frozenset(
    {
        "secure_filename",
        "sanitize_filename",
        "validate_filename",
        "allowed_file",
        "is_allowed_extension",
        "check_extension",
        "validate_extension",
        "validate_mime_type",
        "check_mime_type",
    }
)
_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.files",
        "request.FILES",
        "request.form",
        "request.values",
    }
)


@dataclass
class InsecureFileUploadFinding:
    """A potentially unsafe file upload pattern."""

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
class InsecureFileUploadStats:
    """Aggregate insecure file upload analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_upload_access(node: ast.AST) -> bool:
    source = _request_source(node)
    if source in _REQUEST_SOURCES:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _UPLOAD_ATTRS:
        return True
    if isinstance(node, ast.Subscript):
        return _is_upload_access(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "getlist"}:
            return _is_upload_access(func.value)
    return False


def _is_user_controlled(node: ast.AST) -> bool:
    if _is_upload_access(node):
        return True
    if isinstance(node, ast.Attribute) and node.attr in {"filename", "name", "original_filename"}:
        return True
    if isinstance(node, ast.Subscript) and _is_upload_access(node.value):
        return True
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _is_user_controlled(v.value)
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Name):
        return node.id in {
            "filename",
            "file_name",
            "uploaded_file",
            "file",
            "upload",
            "f",
            "content",
        }
    return False


def _is_secure_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        attr = _call_attr(node)
        if attr in _SECURE_FUNCS:
            return True
    return False


class _InsecureFileUploadVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure file upload risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureFileUploadFinding] = []
        self._function_stack: list[str] = []
        self._has_validation_in_scope = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            InsecureFileUploadFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self._has_validation_in_scope = False
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._has_validation_in_scope = False
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        attr = _call_attr(node)

        if attr in _SECURE_FUNCS:
            self._has_validation_in_scope = True

        if attr in _SAVE_ATTRS and node.args:
            target = node.args[0] if attr == "save" else node
            if _is_user_controlled(target) and not self._has_validation_in_scope:
                self._add(
                    node,
                    "unsanitized_save",
                    severity="high",
                    message="File saved with user-controlled path — sanitize filename and validate extension",
                )

        if attr == "open" and len(node.args) >= 1 and _is_user_controlled(node.args[0]):
            mode = "w"
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if "w" in mode or "a" in mode or "+" in mode:
                self._add(
                    node,
                    "user_controlled_write",
                    severity="high",
                    message="Writing uploaded content to user-controlled path without validation",
                )

        if attr in {"copy", "copyfile", "move", "rename"} and node.args:
            if any(_is_user_controlled(arg) for arg in node.args[:2]):
                self._add(
                    node,
                    "user_controlled_copy",
                    severity="medium",
                    message="File operation uses user-controlled path — validate extension and destination",
                )

        if attr in _UPLOAD_ATTRS or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _UPLOAD_ATTRS
            and _request_source(node.func.value) == "request"
        ):
            self._add(
                node,
                "direct_upload_access",
                severity="low",
                message="File upload accessed — ensure extension, MIME type, and size validation",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_user_controlled(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "filepath",
                    "file_path",
                    "dest",
                    "destination",
                    "save_path",
                }:
                    self._add(
                        node,
                        "user_controlled_path",
                        severity="medium",
                        message="Upload destination derived from user input without sanitization",
                    )
        self.generic_visit(node)


class InsecureFileUploadAnalyzer:
    """Detect insecure file upload handling in web application code.

    Flags unsanitized filenames, user-controlled save paths, and missing
    validation around file upload handlers.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
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
        """Analyze the project and return insecure file upload findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure upload risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 20.0 + medium * 12.0 + low * 5.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Insecure file upload risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure file upload findings."""
        self.analyze()
        lines = [
            "Insecure file upload analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure file upload patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
