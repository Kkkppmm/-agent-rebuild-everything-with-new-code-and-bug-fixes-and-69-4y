"""TestMapper — map source modules to test files and find coverage gaps."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

TEST_DIR_NAMES = {"tests", "test", "testing", "spec"}
TEST_FILE_PREFIXES = ("test_",)
TEST_FILE_SUFFIXES = ("_test.py", "_spec.py")
SOURCE_TEST_PATTERNS = [
    re.compile(r"^test_(.+)\.py$"),
    re.compile(r"^(.+)_test\.py$"),
    re.compile(r"^(.+)_spec\.py$"),
]


@dataclass
class ModuleMapping:
    """Mapping between a source module and its test file(s)."""

    source: str
    tests: list[str] = field(default_factory=list)

    @property
    def has_tests(self) -> bool:
        return bool(self.tests)

    def format(self) -> str:
        """Return a single-line description."""
        if self.tests:
            joined = ", ".join(self.tests)
            return f"{self.source} -> {joined}"
        return f"{self.source} -> (no tests)"


@dataclass
class TestMapReport:
    """Summary of source-to-test mappings for a project."""

    total_modules: int
    tested: int
    untested: list[str] = field(default_factory=list)
    mappings: list[ModuleMapping] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        if self.total_modules == 0:
            return 100.0
        return round(100.0 * self.tested / self.total_modules, 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Test mapping: {self.coverage_pct}% "
            f"({self.tested}/{self.total_modules} modules have tests)",
            f"Untested modules: {len(self.untested)}",
        ]
        return "\n".join(lines)


class TestMapper:
    """Map Python source modules to their test files."""

    def __init__(
        self,
        root: str,
        *,
        source_dir: str = "src",
        test_dir: str = "tests",
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.source_dir = source_dir
        self.test_dir = test_dir
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._report: TestMapReport | None = None

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _is_test_file(self, path: Path) -> bool:
        name = path.name
        if name == "conftest.py":
            return True
        if name.startswith(TEST_FILE_PREFIXES):
            return True
        return any(name.endswith(suffix) for suffix in TEST_FILE_SUFFIXES)

    def _is_test_dir(self, path: Path) -> bool:
        return path.name in TEST_DIR_NAMES

    def _collect_py_files(self, base: Path) -> list[Path]:
        if not base.exists():
            return []
        files: list[Path] = []
        for path in sorted(base.rglob("*.py")):
            if path.is_file() and not self._should_skip(path):
                files.append(path)
        return files

    def _module_key(self, path: Path, base: Path) -> str:
        relative = path.relative_to(base)
        parts = list(relative.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].removesuffix(".py")
        return ".".join(parts)

    def _guess_source_from_test(self, test_name: str) -> str | None:
        for pattern in SOURCE_TEST_PATTERNS:
            match = pattern.match(test_name)
            if match:
                return match.group(1).replace("/", ".").replace("\\", ".")
        return None

    def _find_test_targets(self, test_path: Path, test_base: Path) -> list[str]:
        name = test_path.name
        relative = str(test_path.relative_to(test_base))
        targets: list[str] = []

        guessed = self._guess_source_from_test(name)
        if guessed:
            targets.append(guessed)

        stem = name.removesuffix(".py")
        if stem.startswith("test_"):
            targets.append(stem.removeprefix("test_"))

        return list(dict.fromkeys(targets))

    def map(self) -> TestMapReport:
        """Build source-to-test mappings for the project."""
        if self._report is not None:
            return self._report

        source_base = self.root / self.source_dir
        if not source_base.exists():
            source_base = self.root

        test_base = self.root / self.test_dir
        source_files = [
            p for p in self._collect_py_files(source_base)
            if not self._is_test_file(p) and p.name != "__init__.py"
        ]
        test_files = self._collect_py_files(test_base) if test_base.exists() else []

        test_index: dict[str, list[str]] = {}
        for test_path in test_files:
            if not self._is_test_file(test_path):
                continue
            rel_test = str(test_path.relative_to(self.root))
            for target in self._find_test_targets(test_path, test_base):
                test_index.setdefault(target, []).append(rel_test)

        mappings: list[ModuleMapping] = []
        untested: list[str] = []
        tested = 0

        for source_path in source_files:
            module = self._module_key(source_path, source_base)
            rel_source = str(source_path.relative_to(self.root))
            tests = test_index.get(module, [])
            if not tests:
                short = module.split(".")[-1]
                tests = test_index.get(short, [])

            mapping = ModuleMapping(source=rel_source, tests=tests)
            mappings.append(mapping)
            if mapping.has_tests:
                tested += 1
            else:
                untested.append(rel_source)

        self._report = TestMapReport(
            total_modules=len(mappings),
            tested=tested,
            untested=untested,
            mappings=mappings,
        )
        return self._report

    def untested_modules(self) -> list[str]:
        """Return source files with no matching test file."""
        return self.map().untested

    def summary(self) -> str:
        """Return a human-readable summary."""
        return self.map().summary()

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing test coverage gaps."""
        report = self.map()
        lines = [
            "Test file mapping analysis:",
            report.summary(),
            "",
            "Untested modules:",
        ]
        if not report.untested:
            lines.append("All analyzed modules have matching test files.")
        else:
            for path in report.untested[:limit]:
                lines.append(f"  - {path}")
            if len(report.untested) > limit:
                lines.append(f"... and {len(report.untested) - limit} more")
        return "\n".join(lines)
