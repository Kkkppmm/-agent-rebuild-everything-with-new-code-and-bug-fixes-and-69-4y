"""Jupyter notebook support for DevAI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class NotebookCell:
    """A single cell from a Jupyter notebook."""

    index: int
    cell_type: str
    source: str
    metadata: dict[str, Any] | None = None

    def is_code(self) -> bool:
        """Return True if this is a code cell."""
        return self.cell_type == "code"

    def is_markdown(self) -> bool:
        """Return True if this is a markdown cell."""
        return self.cell_type == "markdown"


class NotebookReader:
    """Read and extract content from Jupyter notebook (.ipynb) files."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Notebook not found: {self.path}")
        if self.path.suffix != ".ipynb":
            raise ValueError(f"Expected .ipynb file, got: {self.path}")

        with self.path.open(encoding="utf-8") as f:
            self._data = json.load(f)

        if "cells" not in self._data:
            raise ValueError(f"Invalid notebook format: missing 'cells' in {self.path}")

    @property
    def cells(self) -> list[NotebookCell]:
        """Return all cells in the notebook."""
        result: list[NotebookCell] = []
        for i, cell in enumerate(self._data["cells"]):
            source = cell.get("source", [])
            if isinstance(source, list):
                text = "".join(source)
            else:
                text = str(source)
            result.append(
                NotebookCell(
                    index=i,
                    cell_type=cell.get("cell_type", "unknown"),
                    source=text,
                    metadata=cell.get("metadata"),
                )
            )
        return result

    def code_cells(self) -> list[NotebookCell]:
        """Return only code cells."""
        return [c for c in self.cells if c.is_code()]

    def markdown_cells(self) -> list[NotebookCell]:
        """Return only markdown cells."""
        return [c for c in self.cells if c.is_markdown()]

    def extract_code(self, *, include_markdown: bool = False) -> str:
        """Extract code from the notebook as a single string."""
        parts: list[str] = []
        for cell in self.cells:
            if cell.is_code():
                parts.append(f"# --- cell {cell.index} ---\n{cell.source}")
            elif include_markdown and cell.is_markdown() and cell.source.strip():
                parts.append(f"# [markdown cell {cell.index}]\n# {cell.source}")
        return "\n\n".join(parts)

    def to_context(self, *, max_cells: int | None = None) -> str:
        """Build LLM context summarizing notebook structure and content."""
        lines = [f"Notebook: {self.path.name}", f"Total cells: {len(self.cells)}"]
        cells = self.cells[:max_cells] if max_cells else self.cells
        for cell in cells:
            preview = cell.source.strip().replace("\n", " ")[:120]
            if len(cell.source.strip()) > 120:
                preview += "..."
            lines.append(f"[{cell.index}] {cell.cell_type}: {preview}")
        return "\n".join(lines)

    def cell_at(self, index: int) -> NotebookCell | None:
        """Return a cell by index, or None if out of range."""
        if 0 <= index < len(self.cells):
            return self.cells[index]
        return None
