"""DependencyParser — parse requirements.txt and pyproject.toml dependencies."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Dependency:
    """A parsed package dependency."""

    name: str
    version: str | None = None
    extras: list[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict[str, str | list[str]]:
        return {
            "name": self.name,
            "version": self.version or "",
            "extras": self.extras,
            "source": self.source,
        }


_REQ_LINE = re.compile(
    r"^([A-Za-z0-9_.\-]+)"
    r"(?:\[(.*?)\])?"
    r"(?:\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;#]+))?"
)


@dataclass
class DependencyParser:
    """Parse Python project dependencies from requirements.txt and pyproject.toml.

    DependencyParser extracts package names, version constraints, and extras
  for dependency audit and update workflows.
    """

    project_path: Path
    _dependencies: list[Dependency] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.project_path = Path(self.project_path).resolve()

    def parse(self) -> list[Dependency]:
        """Parse all dependency sources in the project."""
        self._dependencies.clear()
        self._parse_requirements()
        self._parse_pyproject()
        return list(self._dependencies)

    def by_name(self) -> dict[str, Dependency]:
        """Return dependencies indexed by package name."""
        if not self._dependencies:
            self.parse()
        return {d.name.lower(): d for d in self._dependencies}

    def summary(self) -> dict[str, int | list[dict[str, str | list[str]]]]:
        """Return a summary of parsed dependencies."""
        if not self._dependencies:
            self.parse()
        sources: dict[str, int] = {}
        for d in self._dependencies:
            sources[d.source] = sources.get(d.source, 0) + 1
        return {
            "total": len(self._dependencies),
            "by_source": sources,
            "dependencies": [d.to_dict() for d in self._dependencies],
        }

    def _parse_requirements(self) -> None:
        req_path = self.project_path / "requirements.txt"
        if not req_path.is_file():
            return
        try:
            lines = req_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            dep = self._parse_req_line(line, source="requirements.txt")
            if dep:
                self._dependencies.append(dep)

    def _parse_pyproject(self) -> None:
        pyproject = self.project_path / "pyproject.toml"
        if not pyproject.is_file():
            return
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            return

        data = self._load_toml(text)
        if not data:
            return

        project = data.get("project", {})
        for dep_str in project.get("dependencies", []):
            dep = self._parse_req_line(str(dep_str), source="pyproject.toml")
            if dep:
                self._dependencies.append(dep)

        optional = project.get("optional-dependencies", {})
        for group, deps in optional.items():
            if not isinstance(deps, list):
                continue
            for dep_str in deps:
                dep = self._parse_req_line(str(dep_str), source=f"pyproject.toml[{group}]")
                if dep:
                    self._dependencies.append(dep)

    def _parse_req_line(self, line: str, source: str) -> Dependency | None:
        line = line.split("#", 1)[0].strip()
        match = _REQ_LINE.match(line)
        if not match:
            return None
        name = match.group(1)
        extras_raw = match.group(2)
        op = match.group(3)
        ver = match.group(4)
        extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
        version = f"{op}{ver}" if op and ver else ver
        return Dependency(name=name, version=version, extras=extras, source=source)

    @staticmethod
    def _load_toml(text: str) -> dict[str, Any]:
        try:
            import tomllib

            return tomllib.loads(text)
        except ImportError:
            pass
        try:
            import tomli

            return tomli.loads(text)
        except ImportError:
            return {}
