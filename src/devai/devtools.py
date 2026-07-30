"""DevTools — unified facade for static project analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from devai.deps_parser import Dependency, DependencyParser
from devai.docstring_coverage import DocstringCoverage, DocstringReport
from devai.git_changelog import ChangelogEntry, GitChangelog
from devai.import_graph import CircularImport, ImportEdge, ImportGraph
from devai.secrets import SecretFinding, SecretsScanner
from devai.typing_coverage import TypingCoverage, TypingReport


@dataclass
class DevToolsReport:
    """Aggregated static analysis report for a project."""

    project_path: str
    imports: dict[str, Any]
    secrets: dict[str, Any]
    typing: dict[str, Any]
    docstrings: dict[str, Any]
    dependencies: dict[str, Any]
    changelog: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "imports": self.imports,
            "secrets": self.secrets,
            "typing": self.typing,
            "docstrings": self.docstrings,
            "dependencies": self.dependencies,
            "changelog": self.changelog,
        }

    def issues_count(self) -> int:
        """Count actionable issues across all analyzers."""
        count = 0
        count += self.imports.get("circular_imports", 0)
        count += self.secrets.get("total", 0)
        files_low_typing = len(self.typing.get("files_below_50pct", []))
        files_low_docs = len(self.docstrings.get("files_below_50pct", []))
        count += files_low_typing + files_low_docs
        return count


@dataclass
class DevTools:
    """Unified facade for static project analysis tools.

    DevTools bundles import graph analysis, secrets scanning, typing and
  docstring coverage, dependency parsing, and changelog generation into a
  single entry point for developer workflows and CI gates.

    Example::

        tools = DevTools("./my-project")
        report = tools.full_report()
        print(f"Issues found: {report.issues_count()}")
    """

    project_path: Path

    def __post_init__(self) -> None:
        self.project_path = Path(self.project_path).resolve()

    def import_graph(self) -> ImportGraph:
        """Analyze Python import dependencies."""
        return ImportGraph(self.project_path)

    def secrets_scanner(self) -> SecretsScanner:
        """Scan for hardcoded credentials."""
        return SecretsScanner(self.project_path)

    def typing_coverage(self) -> TypingCoverage:
        """Measure type hint coverage."""
        return TypingCoverage(self.project_path)

    def docstring_coverage(self) -> DocstringCoverage:
        """Measure docstring coverage."""
        return DocstringCoverage(self.project_path)

    def dependency_parser(self) -> DependencyParser:
        """Parse project dependencies."""
        return DependencyParser(self.project_path)

    def git_changelog(self) -> GitChangelog:
        """Generate changelog from git history."""
        return GitChangelog(self.project_path)

    def scan_imports(self) -> dict[str, Any]:
        """Run import graph analysis and return summary."""
        graph = self.import_graph()
        graph.scan()
        return graph.summary()

    def scan_secrets(self) -> dict[str, Any]:
        """Run secrets scan and return summary."""
        return self.secrets_scanner().summary()

    def analyze_typing(self) -> dict[str, Any]:
        """Run typing coverage analysis and return summary."""
        return self.typing_coverage().summary()

    def analyze_docstrings(self) -> dict[str, Any]:
        """Run docstring coverage analysis and return summary."""
        return self.docstring_coverage().summary()

    def parse_dependencies(self) -> dict[str, Any]:
        """Parse dependencies and return summary."""
        return self.dependency_parser().summary()

    def generate_changelog(self, version: str, *, since: str | None = None) -> str:
        """Generate a changelog section for a release."""
        return self.git_changelog().generate(version, since=since)

    def full_report(self, *, changelog_version: str | None = None) -> DevToolsReport:
        """Run all analyzers and return an aggregated report."""
        ig = self.import_graph()
        ig.scan()
        imports_summary = ig.summary()

        secrets_summary = self.secrets_scanner().summary()
        typing_summary = self.typing_coverage().summary()
        docstrings_summary = self.docstring_coverage().summary()
        deps_summary = self.dependency_parser().summary()

        changelog = self.git_changelog()
        changelog.collect()
        changelog_summary = changelog.summary()

        return DevToolsReport(
            project_path=str(self.project_path),
            imports=imports_summary,
            secrets=secrets_summary,
            typing=typing_summary,
            docstrings=docstrings_summary,
            dependencies=deps_summary,
            changelog=changelog_summary,
        )
