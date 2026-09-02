"""DependencyParser — parse and analyze project dependencies."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


REQUIREMENT_RE = re.compile(
    r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*"
    r"(?:\[(?P<extras>[^\]]+)\])?"
    r"(?:\s*(?P<op>[=<>!~]+)\s*(?P<version>[^\s;#]+))?"
    r"(?:\s*;.*)?$"
)


@dataclass
class Dependency:
    """A parsed project dependency."""

    name: str
    version: str | None = None
    operator: str | None = None
    extras: list[str] = field(default_factory=list)
    source: str = "unknown"
    pinned: bool = False

    def format(self) -> str:
        """Return a single-line description."""
        extras = f"[{','.join(self.extras)}]" if self.extras else ""
        if self.version:
            op = self.operator or "=="
            return f"{self.name}{extras} {op} {self.version} ({self.source})"
        return f"{self.name}{extras} (unpinned, {self.source})"


class DependencyParser:
    """Parse dependencies from requirements.txt and pyproject.toml."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._deps: list[Dependency] = []

    def _parse_requirement_line(self, line: str, source: str) -> Dependency | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            return None
        match = REQUIREMENT_RE.match(stripped)
        if not match:
            return None
        name = match.group(1).lower().replace("_", "-")
        extras_raw = match.group("extras")
        extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
        op = match.group("op")
        version = match.group("version")
        pinned = op == "==" and version is not None
        return Dependency(
            name=name,
            version=version,
            operator=op,
            extras=extras,
            source=source,
            pinned=pinned,
        )

    def _parse_requirements_file(self, path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return deps
        for line in lines:
            dep = self._parse_requirement_line(line, str(path.relative_to(self.root)))
            if dep:
                deps.append(dep)
        return deps

    def _parse_pyproject(self, path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return deps

        in_project = False
        in_deps = False
        bracket_depth = 0

        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "[project]":
                in_project = True
                in_deps = False
                continue
            if stripped.startswith("[") and stripped != "[project]":
                in_project = False
                in_deps = False
                continue
            if not in_project:
                continue
            if stripped.startswith("dependencies") and "=" in stripped:
                in_deps = True
                if "[" in stripped and "]" not in stripped:
                    bracket_depth = stripped.count("[") - stripped.count("]")
                elif "[" in stripped and "]" in stripped:
                    inner = stripped.split("[", 1)[1].rsplit("]", 1)[0]
                    for item in inner.split(","):
                        item = item.strip().strip('"').strip("'")
                        if item:
                            dep = self._parse_requirement_line(item, "pyproject.toml")
                            if dep:
                                deps.append(dep)
                    in_deps = False
                continue
            if in_deps:
                bracket_depth += stripped.count("[") - stripped.count("]")
                item = stripped.strip(",").strip('"').strip("'")
                if item and item not in ("[", "]"):
                    dep = self._parse_requirement_line(item, "pyproject.toml")
                    if dep:
                        deps.append(dep)
                if bracket_depth <= 0 and "]" in stripped:
                    in_deps = False
        return deps

    def parse(self) -> list[Dependency]:
        """Parse all dependencies from the project root."""
        if self._deps:
            return self._deps

        deps: list[Dependency] = []
        req_path = self.root / "requirements.txt"
        if req_path.exists():
            deps.extend(self._parse_requirements_file(req_path))

        pyproject = self.root / "pyproject.toml"
        if pyproject.exists():
            deps.extend(self._parse_pyproject(pyproject))

        for req_file in sorted(self.root.glob("requirements*.txt")):
            if req_file.name == "requirements.txt":
                continue
            deps.extend(self._parse_requirements_file(req_file))

        self._deps = deps
        return deps

    def unpinned(self) -> list[Dependency]:
        """Return dependencies without exact version pins."""
        return [d for d in self.parse() if not d.pinned]

    def duplicates(self) -> dict[str, list[Dependency]]:
        """Return dependencies declared in multiple sources."""
        by_name: dict[str, list[Dependency]] = {}
        for dep in self.parse():
            by_name.setdefault(dep.name, []).append(dep)
        return {name: items for name, items in by_name.items() if len(items) > 1}

    def summary(self) -> str:
        """Return a human-readable summary."""
        deps = self.parse()
        unpinned = self.unpinned()
        dupes = self.duplicates()
        lines = [
            f"Dependencies: {len(deps)} total",
            f"Pinned (==): {len(deps) - len(unpinned)}",
            f"Unpinned: {len(unpinned)}",
        ]
        if dupes:
            lines.append(f"Duplicates: {len(dupes)} packages in multiple files")
        return "\n".join(lines)

    def to_context(self) -> str:
        """Build LLM-ready context describing project dependencies."""
        deps = self.parse()
        unpinned = self.unpinned()
        dupes = self.duplicates()
        lines = [
            "Project dependency analysis:",
            self.summary(),
            "",
            "Dependencies:",
        ]
        for dep in deps:
            lines.append(f"  - {dep.format()}")
        if unpinned:
            lines.append("")
            lines.append("Unpinned dependencies (consider pinning):")
            for dep in unpinned:
                lines.append(f"  - {dep.name} ({dep.source})")
        if dupes:
            lines.append("")
            lines.append("Duplicate declarations:")
            for name, items in sorted(dupes.items()):
                sources = ", ".join(d.source for d in items)
                lines.append(f"  - {name}: {sources}")
        return "\n".join(lines)
