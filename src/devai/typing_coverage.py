"""TypingCoverage — analyze type hint coverage across Python source files."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TypingReport:
    """Type hint coverage report for a single file."""

    path: str
    functions: int
    typed_functions: int
    parameters: int
    typed_parameters: int
    returns: int
    typed_returns: int

    @property
    def function_coverage(self) -> float:
        return self.typed_functions / self.functions if self.functions else 1.0

    @property
    def parameter_coverage(self) -> float:
        return self.typed_parameters / self.parameters if self.parameters else 1.0

    @property
    def return_coverage(self) -> float:
        return self.typed_returns / self.returns if self.returns else 1.0

    @property
    def overall_coverage(self) -> float:
        total = self.functions + self.parameters + self.returns
        typed = self.typed_functions + self.typed_parameters + self.typed_returns
        return typed / total if total else 1.0

    def to_dict(self) -> dict[str, str | int | float]:
        return {
            "path": self.path,
            "functions": self.functions,
            "typed_functions": self.typed_functions,
            "parameters": self.parameters,
            "typed_parameters": self.typed_parameters,
            "returns": self.returns,
            "typed_returns": self.typed_returns,
            "overall_coverage": round(self.overall_coverage, 3),
        }


@dataclass
class TypingCoverage:
    """Measure type hint coverage across a Python project.

    TypingCoverage scans function definitions and reports how many parameters
  and return types are annotated — useful for gradual typing adoption.
    """

    root: Path
    _reports: list[TypingReport] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    def analyze(
        self,
        *,
        exclude: frozenset[str] = frozenset({"__pycache__", ".git", ".venv", "venv", "tests"}),
    ) -> list[TypingReport]:
        """Analyze type hint coverage for all Python files."""
        self._reports.clear()

        if not self.root.is_dir():
            raise FileNotFoundError(f"Project root not found: {self.root}")

        for path in sorted(self.root.rglob("*.py")):
            if any(part in exclude for part in path.parts):
                continue
            report = self._analyze_file(path)
            if report.functions > 0:
                self._reports.append(report)

        return list(self._reports)

    def summary(self) -> dict[str, float | int | list[dict[str, str | int | float]]]:
        """Return aggregate coverage statistics."""
        if not self._reports:
            self.analyze()

        total_funcs = sum(r.functions for r in self._reports)
        typed_funcs = sum(r.typed_functions for r in self._reports)
        total_params = sum(r.parameters for r in self._reports)
        typed_params = sum(r.typed_parameters for r in self._reports)
        total_returns = sum(r.returns for r in self._reports)
        typed_returns = sum(r.typed_returns for r in self._reports)

        overall_total = total_funcs + total_params + total_returns
        overall_typed = typed_funcs + typed_params + typed_returns

        return {
            "files": len(self._reports),
            "functions": total_funcs,
            "typed_functions": typed_funcs,
            "function_coverage": round(typed_funcs / total_funcs if total_funcs else 1.0, 3),
            "parameter_coverage": round(typed_params / total_params if total_params else 1.0, 3),
            "return_coverage": round(typed_returns / total_returns if total_returns else 1.0, 3),
            "overall_coverage": round(overall_typed / overall_total if overall_total else 1.0, 3),
            "files_below_50pct": [
                r.to_dict() for r in self._reports if r.overall_coverage < 0.5
            ],
        }

    def _analyze_file(self, path: Path) -> TypingReport:
        rel = str(path.relative_to(self.root))
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return TypingReport(path=rel, functions=0, typed_functions=0, parameters=0, typed_parameters=0, returns=0, typed_returns=0)

        functions = typed_functions = parameters = typed_parameters = returns = typed_returns = 0

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            functions += 1
            has_return = node.returns is not None
            has_params = any(
                arg.annotation is not None
                for arg in node.args.args + node.args.kwonlyargs
                if arg.arg != "self" and arg.arg != "cls"
            )
            if has_return or has_params:
                typed_functions += 1

            for arg in node.args.args:
                if arg.arg in ("self", "cls"):
                    continue
                parameters += 1
                if arg.annotation is not None:
                    typed_parameters += 1

            for arg in node.args.kwonlyargs:
                parameters += 1
                if arg.annotation is not None:
                    typed_parameters += 1

            returns += 1
            if node.returns is not None:
                typed_returns += 1

        return TypingReport(
            path=rel,
            functions=functions,
            typed_functions=typed_functions,
            parameters=parameters,
            typed_parameters=typed_parameters,
            returns=returns,
            typed_returns=typed_returns,
        )
