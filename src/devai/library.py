"""ProgramLibrary — discover, search, and run DevProgram files from a directory."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from devai.assistant import CodeAssistant
from devai.program import DevProgram, ProgramResult

if TYPE_CHECKING:
    from devai.runtime import DevRuntime
    from devai.schedule import DevSchedule

PROGRAM_EXTENSIONS = {".json", ".yaml", ".yml"}


@dataclass
class ProgramEntry:
    """Metadata for a program discovered in a library directory."""

    name: str
    path: Path
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    task_count: int = 0
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "description": self.description,
            "tags": self.tags,
            "task_count": self.task_count,
            "actions": self.actions,
        }


@dataclass
class ProgramLibrary:
    """Load and manage DevProgram files from a directory.

    ProgramLibrary scans a folder for JSON/YAML program files, indexes them
    by name, and provides search and run helpers for developer workflows.
    """

    directory: Path
    assistant: CodeAssistant
    _entries: dict[str, ProgramEntry] = field(default_factory=dict, init=False, repr=False)
    _programs: dict[str, DevProgram] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.directory = Path(self.directory).resolve()

    def discover(self, *, recursive: bool = False) -> list[ProgramEntry]:
        """Scan the directory for program files and build the index."""
        self._entries.clear()
        self._programs.clear()
        if not self.directory.is_dir():
            raise FileNotFoundError(f"Program library directory not found: {self.directory}")

        paths = (
            sorted(self.directory.rglob("*"))
            if recursive
            else sorted(self.directory.iterdir())
        )
        for path in paths:
            if not path.is_file() or path.suffix not in PROGRAM_EXTENSIONS:
                continue
            program = DevProgram.from_file(path, self.assistant)
            key = program.name
            if key in self._entries:
                key = f"{key}-{path.stem}"
            entry = ProgramEntry(
                name=key,
                path=path,
                description=self._read_description(path, program),
                tags=self._read_tags(path),
                task_count=len(program.tasks),
                actions=[task.action for task in program.tasks],
            )
            self._entries[key] = entry
            self._programs[key] = program

        return list(self._entries.values())

    def list(self) -> list[ProgramEntry]:
        """Return indexed program entries (discover first if empty)."""
        if not self._entries:
            self.discover()
        return list(self._entries.values())

    def get(self, name: str) -> DevProgram:
        """Return a program by name."""
        if not self._programs:
            self.discover()
        if name not in self._programs:
            available = ", ".join(sorted(self._programs)) or "(none)"
            raise KeyError(f"Program '{name}' not found. Available: {available}")
        return self._programs[name]

    def get_entry(self, name: str) -> ProgramEntry:
        """Return metadata for a program by name."""
        if not self._entries:
            self.discover()
        if name not in self._entries:
            raise KeyError(f"Program '{name}' not found")
        return self._entries[name]

    def search(self, query: str) -> list[ProgramEntry]:
        """Search programs by name, description, tags, or actions."""
        if not self._entries:
            self.discover()
        needle = query.lower().strip()
        if not needle:
            return self.list()

        matches: list[ProgramEntry] = []
        for entry in self._entries.values():
            haystack = " ".join(
                [
                    entry.name,
                    entry.description or "",
                    " ".join(entry.tags),
                    " ".join(entry.actions),
                    entry.path.stem,
                ]
            ).lower()
            if needle in haystack:
                matches.append(entry)
        return matches

    def run(self, name: str, context: dict[str, str]) -> list[ProgramResult]:
        """Load and execute a program by name."""
        return self.get(name).run(context)

    async def arun(self, name: str, context: dict[str, str]) -> list[ProgramResult]:
        """Load and execute a program asynchronously."""
        return await self.get(name).arun(context)

    def validate_all(self) -> dict[str, list[str]]:
        """Validate every program in the library."""
        if not self._programs:
            self.discover()
        return {name: program.validate() for name, program in self._programs.items()}

    def create_schedule(
        self,
        runtime: "DevRuntime",
        config_path: str | Path,
    ) -> "DevSchedule":
        """Build a DevSchedule from a config file referencing programs in this library."""
        from devai.schedule_config import schedule_from_config

        return schedule_from_config(runtime, config_path, library=self)

    @staticmethod
    def _read_description(path: Path, program: DevProgram) -> str | None:
        if path.suffix in {".yaml", ".yml"}:
            try:
                import yaml
            except ImportError:
                return None
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                desc = data.get("description")
                return str(desc) if desc else None
        if path.suffix == ".json":
            import json

            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                desc = data.get("description")
                return str(desc) if desc else None
        if program.tasks:
            return f"{len(program.tasks)}-step program ({program.tasks[0].action})"
        return None

    @staticmethod
    def _read_tags(path: Path) -> list[str]:
        if path.suffix not in {".yaml", ".yml", ".json"}:
            return []
        try:
            if path.suffix in {".yaml", ".yml"}:
                import yaml

                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            else:
                import json

                data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        tags = data.get("tags", [])
        if isinstance(tags, list):
            return [str(tag) for tag in tags]
        return []
