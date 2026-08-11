"""EnvVarAnalyzer — inventory environment variables and detect config drift."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_ENV_FILE_NAMES = (".env.example", ".env.sample", ".env.local", ".env")
_ENV_ATTRS = frozenset({"get", "getenv", "environ"})
_EXPORT_RE = re.compile(r"^\s*export\s+", re.IGNORECASE)


@dataclass
class EnvVarDefinition:
    """An environment variable declared in an env file."""

    name: str
    source: str
    lineno: int | None = None
    has_value: bool = False
    is_documented: bool = False
    comment: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.source}:{self.lineno}" if self.lineno else self.source
        flags: list[str] = []
        if not self.has_value:
            flags.append("empty")
        if self.is_documented:
            flags.append("documented")
        suffix = f" ({', '.join(flags)})" if flags else ""
        return f"{loc} {self.name}{suffix}"


@dataclass
class EnvVarReference:
    """A reference to an environment variable in source code."""

    name: str
    path: str
    lineno: int
    pattern: str

    def format(self) -> str:
        """Return a single-line description."""
        return f"{self.path}:{self.lineno} {self.name} via {self.pattern}"


@dataclass
class EnvVarGap:
    """A mismatch between env files and code references."""

    name: str
    kind: str
    severity: str
    message: str
    references: list[EnvVarReference] = field(default_factory=list)

    def format(self) -> str:
        """Return a single-line description."""
        refs = ""
        if self.references:
            refs = f" ({self.references[0].path}:{self.references[0].lineno})"
        return f"[{self.severity}] {self.name} — {self.message}{refs}"


@dataclass
class EnvVarStats:
    """Aggregate environment variable analysis statistics."""

    defined: int
    referenced: int
    documented: int
    gaps: int
    example_vars: int = 0
    runtime_vars: int = 0


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _parse_env_file(path: Path, source: str) -> list[EnvVarDefinition]:
    """Parse KEY=VALUE lines from an env file."""
    definitions: list[EnvVarDefinition] = []
    pending_comment = ""

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            pending_comment = ""
            continue
        if line.startswith("#"):
            pending_comment = line.lstrip("#").strip()
            continue

        if line.startswith("export "):
            line = line[7:].strip()

        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            pending_comment = ""
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        definitions.append(
            EnvVarDefinition(
                name=key,
                source=source,
                lineno=lineno,
                has_value=bool(value),
                is_documented=bool(pending_comment),
                comment=pending_comment,
            )
        )
        pending_comment = ""

    return definitions


class _EnvVarVisitor(ast.NodeVisitor):
    """AST visitor that finds environment variable references."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.references: list[EnvVarReference] = []

    def _add(self, name: str, lineno: int, pattern: str) -> None:
        if name and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            self.references.append(EnvVarReference(name=name, path=self.path, lineno=lineno, pattern=pattern))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ENV_ATTRS:
            if node.args:
                key = _string_value(node.args[0])
                if key:
                    self._add(key, node.lineno, f"os.{func.attr}")
            for kw in node.keywords:
                if kw.arg == "key":
                    key = _string_value(kw.value)
                    if key:
                        self._add(key, node.lineno, f"os.{func.attr}")
        elif isinstance(func, ast.Name) and func.id == "getenv":
            if node.args:
                key = _string_value(node.args[0])
                if key:
                    self._add(key, node.lineno, "getenv")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
            key = _string_value(node.slice)
            if key:
                self._add(key, node.lineno, "os.environ[]")
        self.generic_visit(node)


class EnvVarAnalyzer:
    """Inventory environment variables and detect drift between code and env files.

    Scans ``.env``, ``.env.example``, and Python sources for ``os.getenv``,
    ``os.environ``, and related patterns. Reports missing documentation,
    unused declarations, and variables referenced in code but absent from
    ``.env.example``.
    """

    def __init__(
        self,
        root: str,
        *,
        env_files: tuple[str, ...] = _ENV_FILE_NAMES,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.env_files = env_files
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._definitions: list[EnvVarDefinition] = []
        self._references: list[EnvVarReference] = []
        self._gaps: list[EnvVarGap] = []
        self._stats: EnvVarStats | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _load_definitions(self) -> list[EnvVarDefinition]:
        definitions: list[EnvVarDefinition] = []
        for name in self.env_files:
            path = self.root / name
            if path.is_file():
                definitions.extend(_parse_env_file(path, name))
        return definitions

    def _scan_references(self) -> list[EnvVarReference]:
        references: list[EnvVarReference] = []
        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            relative = str(path.relative_to(self.root))
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=relative)
            except (OSError, SyntaxError):
                continue
            visitor = _EnvVarVisitor(relative)
            visitor.visit(tree)
            references.extend(visitor.references)
        return references

    def definitions(self) -> list[EnvVarDefinition]:
        """Return env var definitions from env files."""
        if not self._definitions:
            self._definitions = self._load_definitions()
        return self._definitions

    def references(self) -> list[EnvVarReference]:
        """Return env var references found in Python source."""
        if not self._references:
            self._references = self._scan_references()
        return self._references

    def analyze(self) -> list[EnvVarGap]:
        """Detect gaps between env files and code references."""
        if self._gaps and self._stats is not None:
            return self._gaps

        definitions = self.definitions()
        references = self.references()
        gaps: list[EnvVarGap] = []

        example_names = {d.name for d in definitions if d.source in {".env.example", ".env.sample"}}
        runtime_names = {d.name for d in definitions if d.source in {".env", ".env.local"}}
        all_defined = {d.name for d in definitions}
        referenced_names = {r.name for r in references}
        refs_by_name: dict[str, list[EnvVarReference]] = {}
        for ref in references:
            refs_by_name.setdefault(ref.name, []).append(ref)

        defs_by_name: dict[str, list[EnvVarDefinition]] = {}
        for definition in definitions:
            defs_by_name.setdefault(definition.name, []).append(definition)

        for name in sorted(referenced_names - example_names):
            refs = refs_by_name.get(name, [])
            gaps.append(
                EnvVarGap(
                    name=name,
                    kind="missing_from_example",
                    severity="high",
                    message="referenced in code but missing from .env.example",
                    references=refs,
                )
            )

        for name in sorted(example_names - referenced_names):
            gaps.append(
                EnvVarGap(
                    name=name,
                    kind="unused_in_code",
                    severity="low",
                    message="declared in .env.example but not referenced in code",
                )
            )

        for name in sorted(referenced_names & example_names):
            defs = defs_by_name.get(name, [])
            example_defs = [d for d in defs if d.source in {".env.example", ".env.sample"}]
            if example_defs and not any(d.has_value for d in example_defs):
                gaps.append(
                    EnvVarGap(
                        name=name,
                        kind="empty_value",
                        severity="medium",
                        message="referenced in code but has empty value in .env.example",
                        references=refs_by_name.get(name, []),
                    )
                )
            if example_defs and not any(d.is_documented for d in example_defs):
                gaps.append(
                    EnvVarGap(
                        name=name,
                        kind="undocumented",
                        severity="low",
                        message="present in .env.example without a comment",
                        references=refs_by_name.get(name, []),
                    )
                )

        for name in sorted(referenced_names - runtime_names - all_defined):
            if name in example_names:
                continue
            refs = refs_by_name.get(name, [])
            gaps.append(
                EnvVarGap(
                    name=name,
                    kind="missing_from_env",
                    severity="medium",
                    message="referenced in code but not declared in any env file",
                    references=refs,
                )
            )

        documented = sum(
            1
            for name in example_names
            if any(d.is_documented for d in defs_by_name.get(name, []))
        )
        self._gaps = gaps
        self._stats = EnvVarStats(
            defined=len(all_defined),
            referenced=len(referenced_names),
            documented=documented,
            gaps=len(gaps),
            example_vars=len(example_names),
            runtime_vars=len(runtime_names),
        )
        return gaps

    @property
    def stats(self) -> EnvVarStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no gaps)."""
        self.analyze()
        stats = self.stats
        if stats.referenced == 0 and stats.defined == 0:
            return 100.0
        high = sum(1 for g in self._gaps if g.severity == "high")
        medium = sum(1 for g in self._gaps if g.severity == "medium")
        low = sum(1 for g in self._gaps if g.severity == "low")
        penalty = high * 20.0 + medium * 10.0 + low * 3.0
        return round(max(0.0, 100.0 - penalty), 1)

    def generate_example(self) -> str:
        """Scaffold a .env.example from code references."""
        self.analyze()
        lines = ["# Generated by DevAI EnvVarAnalyzer", ""]
        referenced = sorted({r.name for r in self.references()})
        defs_by_name = {d.name: d for d in self.definitions()}

        for name in referenced:
            existing = defs_by_name.get(name)
            if existing and existing.comment:
                lines.append(f"# {existing.comment}")
            lines.append(f"{name}=")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            (
                f"Env vars: {stats.defined} defined, {stats.referenced} referenced, "
                f"{stats.gaps} gap(s)"
            ),
            f"  .env.example: {stats.example_vars} vars ({stats.documented} documented)",
            f"  runtime env files: {stats.runtime_vars} vars",
        ]
        high = [g for g in self._gaps if g.severity == "high"]
        if high:
            lines.append(f"  {len(high)} high-severity gap(s) — sync .env.example with code")
        return "\n".join(lines)

    def to_context(self, limit: int = 40) -> str:
        """Build LLM-ready context describing env var drift."""
        self.analyze()
        lines = [
            "Environment variable analysis:",
            self.summary(),
            "",
            "Gaps:",
        ]
        if not self._gaps:
            lines.append("No env var drift detected.")
        else:
            for gap in self._gaps[:limit]:
                lines.append(f"  {gap.format()}")
            if len(self._gaps) > limit:
                lines.append(f"  ... and {len(self._gaps) - limit} more")
        return "\n".join(lines)
