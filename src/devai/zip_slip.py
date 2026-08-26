"""ZipSlipAnalyzer — detect archive extraction without path validation."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_UNPACK_ARCHIVE = re.compile(r"\bshutil\.unpack_archive\s*\(")
_EXTRACTALL = re.compile(r"\.extractall\s*\(")


@dataclass
class ZipSlipFinding:
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
class ZipSlipStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _ZipSlipVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ZipSlipFinding] = []
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

    def _has_filter_kwarg(self, node: ast.Call) -> bool:
        return any(kw.arg == "filter" for kw in node.keywords)

    def _is_literal_member(self, node: ast.expr | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "extractall":
                self.findings.append(
                    ZipSlipFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unsafe_extractall",
                        severity="high",
                        message=(
                            "extractall() without member path validation is vulnerable to zip-slip — "
                            "validate each member name before extraction"
                        ),
                        function=self._current_function(),
                    )
                )
            elif func.attr == "extract":
                member = node.args[0] if node.args else None
                if not self._is_literal_member(member):
                    self.findings.append(
                        ZipSlipFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="dynamic_extract",
                            severity="medium",
                            message=(
                                "Extracting archive members from variables may allow path traversal — "
                                "reject names containing '..' or absolute paths"
                            ),
                            function=self._current_function(),
                        )
                    )
            elif func.attr == "unpack_archive":
                self.findings.append(
                    ZipSlipFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unsafe_unpack_archive",
                        severity="high",
                        message=(
                            "shutil.unpack_archive() without path validation is vulnerable to zip-slip"
                        ),
                        function=self._current_function(),
                    )
                )

        if isinstance(func, ast.Name) and func.id == "unpack_archive":
            self.findings.append(
                ZipSlipFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="unsafe_unpack_archive",
                    severity="high",
                    message="unpack_archive() without path validation is vulnerable to zip-slip",
                    function=self._current_function(),
                )
            )

        if (
            isinstance(func, ast.Attribute)
            and func.attr == "extractall"
            and not self._has_filter_kwarg(node)
            and self._looks_like_tarfile_call(func)
        ):
            self.findings.append(
                ZipSlipFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="tarfile_no_filter",
                    severity="medium",
                    message="tarfile.extractall() should use filter='data' (Python 3.12+) to block unsafe members",
                    function=self._current_function(),
                )
            )

        self.generic_visit(node)

    def _looks_like_tarfile_call(self, func: ast.Attribute) -> bool:
        value = func.value
        if isinstance(value, ast.Name) and value.id in {"tar", "archive", "tarfile"}:
            return True
        if isinstance(value, ast.Call):
            call_func = value.func
            if isinstance(call_func, ast.Attribute) and call_func.attr == "open":
                return True
            if isinstance(call_func, ast.Name) and call_func.id == "TarFile":
                return True
        return False


class ZipSlipAnalyzer:
    """Detect zip-slip vulnerabilities in archive extraction code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ZipSlipFinding] = []
        self._stats: ZipSlipStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[ZipSlipFinding]:
        findings: list[ZipSlipFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _UNPACK_ARCHIVE.search(line):
                findings.append(
                    ZipSlipFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="unsafe_unpack_archive",
                        severity="high",
                        message="shutil.unpack_archive() without path validation is vulnerable to zip-slip",
                    )
                )
            if _EXTRACTALL.search(line) and "filter=" not in line:
                findings.append(
                    ZipSlipFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="unsafe_extractall",
                        severity="high",
                        message=(
                            "extractall() without member path validation is vulnerable to zip-slip"
                        ),
                    )
                )
        return findings

    def analyze(self) -> list[ZipSlipFinding]:
        if self._findings:
            return self._findings

        findings: list[ZipSlipFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()
        seen: set[tuple[str, int, str]] = set()

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
            visitor = _ZipSlipVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            combined = visitor.findings + line_findings
            deduped: list[ZipSlipFinding] = []
            for finding in combined:
                key = (finding.path, finding.lineno, finding.pattern)
                if key not in seen:
                    seen.add(key)
                    deduped.append(finding)
            if deduped:
                files_with_findings.add(rel)
            findings.extend(deduped)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = ZipSlipStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ZipSlipStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 12.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Zip-slip risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Zip-slip analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No unsafe archive extraction patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
