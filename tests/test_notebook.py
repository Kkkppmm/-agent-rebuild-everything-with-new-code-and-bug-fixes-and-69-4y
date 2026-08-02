"""Tests for DevAI notebook support."""

import json
import tempfile
from pathlib import Path

import pytest

from devai import CodeAssistant, NotebookCell, NotebookReader
from devai.core import MockLLMClient


def _make_notebook(path: Path) -> None:
  notebook = {
      "nbformat": 4,
      "nbformat_minor": 5,
      "metadata": {},
      "cells": [
          {
              "cell_type": "markdown",
              "metadata": {},
              "source": ["# Demo\n", "A test notebook."],
          },
          {
              "cell_type": "code",
              "metadata": {},
              "source": ["def add(a, b):\n", "    return a + b\n"],
              "outputs": [],
          },
          {
              "cell_type": "code",
              "metadata": {},
              "source": ["x = 1\n"],
              "outputs": [],
          },
      ],
  }
  path.write_text(json.dumps(notebook), encoding="utf-8")


class TestNotebookReader:
    def test_read_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            reader = NotebookReader(path)
            assert len(reader.cells) == 3
            assert reader.cells[0].is_markdown()
            assert reader.cells[1].is_code()

    def test_extract_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            reader = NotebookReader(path)
            code = reader.extract_code()
            assert "def add(a, b)" in code
            assert "cell 1" in code

    def test_code_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            reader = NotebookReader(path)
            assert len(reader.code_cells()) == 2

    def test_to_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            reader = NotebookReader(path)
            context = reader.to_context()
            assert "demo.ipynb" in context
            assert "markdown" in context

    def test_cell_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            reader = NotebookReader(path)
            cell = reader.cell_at(1)
            assert cell is not None
            assert cell.is_code()
            assert reader.cell_at(99) is None

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            NotebookReader("/nonexistent/notebook.ipynb")

    def test_invalid_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".txt") as tmp:
            with pytest.raises(ValueError, match="Expected .ipynb"):
                NotebookReader(tmp.name)


class TestNotebookAssistant:
    def test_review_notebook(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            client = MockLLMClient(default_response="Notebook review complete.")
            assistant = CodeAssistant(client=client)
            result = assistant.review_notebook(str(path))
            assert result == "Notebook review complete."

    def test_review_notebook_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.ipynb"
            _make_notebook(path)
            client = MockLLMClient(default_response="Cell review.")
            assistant = CodeAssistant(client=client)
            results = assistant.review_notebook_cells(str(path))
            assert 1 in results
            assert 2 in results
            assert len(results) == 2

    def test_analyze_test_failures(self):
        client = MockLLMClient(default_response="Fix the assertion.")
        assistant = CodeAssistant(client=client)
        result = assistant.analyze_test_failures("FAILED test_add", code="def add(a,b): pass")
        assert result == "Fix the assertion."

    def test_analyze_stacktrace(self):
        client = MockLLMClient(default_response="KeyError on line 5.")
        assistant = CodeAssistant(client=client)
        result = assistant.analyze_stacktrace("Traceback...", context="user lookup")
        assert result == "KeyError on line 5."

    def test_review_config(self):
        client = MockLLMClient(default_response="Config looks good.")
        assistant = CodeAssistant(client=client)
        result = assistant.review_config("[tool.pytest]", config_type="pyproject.toml")
        assert result == "Config looks good."
