"""Scaffold a new DevAI project for developers and programs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devai.config_file import config_file_template


@dataclass
class ScaffoldResult:
    """Paths created by :func:`scaffold_project`."""

    root: Path
    created: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.created)


def _write_file(path: Path, content: str, *, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def _pre_commit_program() -> str:
    return (
        "name: pre-commit\n"
        "description: Review, security scan, and docstring check before commit\n"
        "tasks:\n"
        "  - name: review\n"
        "    action: review\n"
        "  - name: security\n"
        "    action: security\n"
        "  - name: docstrings\n"
        "    action: docstring\n"
    )


def _schedule_config() -> str:
    return (
        "# DevAI scheduled jobs — program names resolve under programs/\n"
        "jobs:\n"
        "  - name: hourly-health\n"
        "    cron: \"0 * * * *\"\n"
        "    program: pre-commit\n"
        "    context:\n"
        "      code: \"${file:src/main.py}\"\n"
    )


def _starter_script() -> str:
    return '''\
"""Starter script for a DevAI-powered developer tool."""

from devai import DevAI


def main() -> None:
    ai = DevAI.from_project(use_mock=True)
    sample = "def add(a, b):\\n    return a + b\\n"
    print(ai.review(sample))
    result = ai.run("pre-commit", {"code": sample})
    print(f"Program steps: {len(result.results)}")


if __name__ == "__main__":
    main()
'''


def scaffold_project(
    path: str | Path = ".",
    *,
    provider: str = "openai",
    model: str = "gpt-4o-mini",
    force: bool = False,
    include_schedule: bool = True,
    include_starter: bool = True,
) -> ScaffoldResult:
    """Create a DevAI project layout with config, programs, and optional schedule.

    Creates:
    - ``.devai.yaml`` — project LLM configuration
    - ``programs/pre-commit.yaml`` — example DevProgram workflow
    - ``devai-schedule.yaml`` — optional cron job definitions
    - ``devai_main.py`` — optional starter Python entry point
    """
    root = Path(path).resolve()
    result = ScaffoldResult(root=root)

    files: list[tuple[Path, str]] = [
        (root / ".devai.yaml", config_file_template(provider=provider, model=model)),
        (root / "programs" / "pre-commit.yaml", _pre_commit_program()),
    ]
    if include_schedule:
        files.append((root / "devai-schedule.yaml", _schedule_config()))
    if include_starter:
        files.append((root / "devai_main.py", _starter_script()))

    for file_path, content in files:
        if _write_file(file_path, content, force=force):
            result.created.append(file_path)
        else:
            result.skipped.append(file_path)

    return result
