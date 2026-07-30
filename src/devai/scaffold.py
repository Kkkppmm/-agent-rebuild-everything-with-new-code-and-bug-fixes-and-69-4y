"""scaffold_project — bootstrap a new DevAI-powered Python project."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScaffoldResult:
    """Result of scaffolding a new project."""

    root: Path
    created: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary of scaffolded files."""
        lines = [f"Scaffolded project at {self.root}"]
        if self.created:
            lines.append(f"Created {len(self.created)} file(s):")
            for path in self.created:
                lines.append(f"  + {path.relative_to(self.root)}")
        if self.skipped:
            lines.append(f"Skipped {len(self.skipped)} existing file(s):")
            for path in self.skipped:
                lines.append(f"  ~ {path.relative_to(self.root)}")
        return "\n".join(lines)


def _write_file(
    path: Path,
    content: str,
    *,
    overwrite: bool,
    result: ScaffoldResult,
) -> None:
    if path.exists() and not overwrite:
        result.skipped.append(path)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    result.created.append(path)


def scaffold_project(
    path: str | Path,
    *,
    name: str | None = None,
    package: str | None = None,
    overwrite: bool = False,
) -> ScaffoldResult:
    """Bootstrap a new DevAI-powered Python project layout.

    Creates a minimal src-layout project with tests, examples, and a
    ``.devai.yaml`` config file ready for LLM-powered dev workflows.

    Args:
        path: Target directory for the new project.
        name: Human-readable project name (defaults to directory name).
        package: Python package name (defaults to normalized directory name).
        overwrite: Replace existing files when True.

    Returns:
        ScaffoldResult with lists of created and skipped files.
    """
    root = Path(path).resolve()
    project_name = name or root.name.replace("-", " ").replace("_", " ").title()
    pkg = package or root.name.lower().replace("-", "_").replace(" ", "_")
    if not pkg.isidentifier():
        pkg = "app"

    result = ScaffoldResult(root=root)

    files: dict[str, str] = {
        "pyproject.toml": f'''[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "{pkg}"
version = "0.1.0"
description = "{project_name} — powered by DevAI"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "devai>=3.4.0",
    "httpx>=0.27.0",
    "pydantic>=2.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "ruff>=0.4.0",
]

[tool.hatch.build.targets.wheel]
packages = ["src/{pkg}"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
''',
        "README.md": f"""# {project_name}

A Python project powered by [DevAI](https://github.com/Kkkppmm/-agent-rebuild-everything-with-new-code-and-bug-fixes-and-69-4y).

## Quick Start

```bash
pip install -e ".[dev]"
python examples/basic_usage.py
```

## DevAI

```python
from devai import DevAI

ai = DevAI.mock()
print(ai.review("def add(a, b): return a + b"))
```
""",
        ".devai.yaml": f"""# DevAI project configuration
provider: openai
model: gpt-4o-mini
# api_key: ${{env:OPENAI_API_KEY}}
project:
  name: {project_name}
  package: {pkg}
""",
        ".gitignore": """__pycache__/
*.py[cod]
.venv/
.env
dist/
build/
*.egg-info/
.pytest_cache/
.ruff_cache/
""",
        f"src/{pkg}/__init__.py": f'"""{project_name} package."""\n\n__version__ = "0.1.0"\n',
        f"src/{pkg}/main.py": f'''"""Main entry point for {project_name}."""


def run() -> None:
    """Run the application."""
    print("Hello from {project_name}!")


if __name__ == "__main__":
    run()
''',
        f"tests/test_{pkg}.py": f'''"""Tests for {pkg}."""

from {pkg} import __version__


def test_version():
    assert __version__ == "0.1.0"
''',
        "examples/basic_usage.py": '''"""Basic DevAI usage example."""

from devai import DevAI

ai = DevAI.mock()
code = "def add(a, b): return a + b"
print(ai.review(code))
''',
        "examples/devtools_example.py": '''"""DevAI static analysis example."""

from devai import DevTools

tools = DevTools(".")
print(tools.summary())
''',
    }

    for rel_path, content in files.items():
        _write_file(root / rel_path, content, overwrite=overwrite, result=result)

    return result
