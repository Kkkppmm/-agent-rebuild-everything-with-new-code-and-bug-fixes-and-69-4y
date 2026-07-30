"""DocstringCoverage — analyze docstring coverage across Python source files."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DocstringReport:
    """Docstring coverage report for a single file."""

    path: str
    modules: int
    documented_modules: int
    classes: int
    documented_classes: int
    functions: int
    documented_functions: int

    @property
    def overall_coverage(self) -> float:
        total = self.modules + self.classes + self.functions
        documented = self.documented_modules + self.documented_classes + self.documented_functions
        return documented / total if total else 1.0

    def to_dict(self) -> dict[str, str | int | float]:
        return {
            "path": self.path,
            "modules": self.modules,
            "documented_modules": self.documented_modules,
            "classes": self.classes,
            "documented_classes": self.documented_classes,
            "functions": self.functions,
            "documented_functions": self.documented_functions,
            "overall_coverage": round(self.overall_coverage, 3),
        }


def _has_docstring(node: ast.AST) -> bool:
    return bool(ast.get_docstring(node))


@dataclass
class DocstringCoverage:
    """Measure docstring coverage across a Python project.

    DocstringCoverage reports which modules, classes, and functions lack
  docstrings — useful for documentation quality gates in CI.
    """

    root: Path
    _reports: list[DocstringReport] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    def analyze(
        self,
        *,
        exclude: frozenset[str] = frozenset({"__pycache__", ".git", ".venv", "venv"}),
    ) -> list[DocstringReport]:
        """Analyze docstring coverage for all Python files."""
        self._reports.clear()

        if not self.root.is_dir():
            raise FileNotFoundError(f"Project root not found: {self.root}")

        for path in sorted(self.root.rglob("*.py")):
            if any(part in exclude for part in path.parts):
                continue
            report = self._analyze_file(path)
            total = report.modules + report.classes + report.functions
            if total > 0:
                self._reports.append(report)

        return list(self._reports)

    def summary(self) -> dict[str, float | int | list[dict[str, str | int | float]]]:
        """Return aggregate docstring coverage statistics."""
        if not self._reports:
            self.analyze()

        modules = sum(r.modules for r in self._reports)
        doc_modules = sum(r.documented_modules for r in self._reports)
        classes = sum(r.classes for r in self._reports)
        doc_classes = sum(r.documented_classes for r in self._reports)
        functions = sum(r.functions for r in self._reports)
        doc_functions = sum(r.documented_functions for r in self._reports)

        total = modules + classes + functions
        documented = doc_modules + doc_classes + doc_functions

        return {
            "files": len(self._reports),
            "modules": modules,
            "documented_modules": doc_modules,
            "classes": classes,
            "documented_classes": doc_classes,
            "functions": functions,
            "documented_functions": doc_functions,
            "overall_coverage": round(documented / total if total else 1.0, 3),
            "files_below_50pct": [
                r.to_dict() for r in self._reports if r.overall_coverage < 0.5
            ],
        }

    def missing(self) -> list[dict[str, str]]:
        """Return a list of undocumented symbols."""
        if not self._reports:
            self.analyze()

        missing: list[dict[str, str]] = []
        for path in sorted(self.root.rglob("*.py")):
            if any(part in {"__pycache__", ".git", ".venv", "venv"} for part in path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(self.root))
            if not _has_docstring(tree):
                missing.append({"path": rel, "kind": "module", "name": rel})

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and not _has_docstring(node):
                    missing.append({"path": rel, "kind": "class", "name": node.name})
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not _has_docstring(node):
                    if node.name.startswith("_") and node.name != "__init__":
                        continue
                    missing.append({"path": rel, "kind": "function", "name": node.name})

        return missing

    def _analyze_file(self, path: Path) -> DocstringReport:
        rel = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return DocstringReport(
                path=rel, modules=0, documented_modules=0,
                classes=0, documented_classes=0, functions=0, documented_functions=0,
            )

        modules = 1
        documented_modules = 1 if _has_docstring(tree) else 0
        classes = documented_classes = functions = documented_functions = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes += 1
                if _has_docstring(node):
                    documented_classes += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if _has_docstring(node):
                    documented_functions += 1

        return DocstringReport(
            path=rel,
            modules=modules,
            documented_modules=documented_modules,
            classes=classes,
            documented_classes=documented_classes,
            functions=functions,
            documented_functions=documented_functions,
        )
