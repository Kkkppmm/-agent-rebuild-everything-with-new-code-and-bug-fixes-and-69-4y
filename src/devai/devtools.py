"""DevTools — unified facade for static project analysis tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devai.deps_parser import Dependency, DependencyParser
from devai.docstring_coverage import DocstringCoverage, DocstringGap, DocstringStats
from devai.git_changelog import CommitInfo, GitChangelog
from devai.import_graph import ImportEdge, ImportGraph
from devai.secrets import SecretFinding, SecretsScanner
from devai.typing_coverage import TypingCoverage, TypingGap, TypingStats


@dataclass
class DevToolsReport:
    """Aggregated static analysis report for a project."""

    root: str
    imports_summary: str = ""
    secrets_summary: str = ""
    typing_summary: str = ""
    docstring_summary: str = ""
    deps_summary: str = ""
    circular_imports: list[list[str]] = field(default_factory=list)
    secret_findings: list[SecretFinding] = field(default_factory=list)
    typing_gaps: list[TypingGap] = field(default_factory=list)
    docstring_gaps: list[DocstringGap] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable multi-section summary."""
        sections = [
            f"DevTools report for {self.root}",
            "",
            "== Imports ==",
            self.imports_summary or "(not scanned)",
            "",
            "== Secrets ==",
            self.secrets_summary or "(not scanned)",
            "",
            "== Typing ==",
            self.typing_summary or "(not scanned)",
            "",
            "== Docstrings ==",
            self.docstring_summary or "(not scanned)",
            "",
            "== Dependencies ==",
            self.deps_summary or "(not scanned)",
        ]
        if self.circular_imports:
            sections.extend(["", "== Circular Imports =="])
            for cycle in self.circular_imports[:5]:
                sections.append(f"  {' -> '.join(cycle)}")
        return "\n".join(sections)

    def to_context(self) -> str:
        """Build LLM-ready context from all scanned sections."""
        parts: list[str] = [f"Static analysis for project: {self.root}", ""]
        if self.imports_summary:
            parts.extend(["Import analysis:", self.imports_summary, ""])
        if self.circular_imports:
            parts.append("Circular imports detected:")
            for cycle in self.circular_imports[:10]:
                parts.append(f"  {' -> '.join(cycle)}")
            parts.append("")
        if self.secrets_summary:
            parts.extend(["Secrets scan:", self.secrets_summary, ""])
            if self.secret_findings:
                parts.append("Findings:")
                for finding in self.secret_findings[:20]:
                    parts.append(f"  - {finding.format()}")
                parts.append("")
        if self.typing_summary:
            parts.extend(["Typing coverage:", self.typing_summary, ""])
            if self.typing_gaps:
                parts.append("Top typing gaps:")
                for gap in self.typing_gaps[:15]:
                    parts.append(f"  - {gap.format()}")
                parts.append("")
        if self.docstring_summary:
            parts.extend(["Docstring coverage:", self.docstring_summary, ""])
            if self.docstring_gaps:
                parts.append("Top docstring gaps:")
                for gap in self.docstring_gaps[:15]:
                    parts.append(f"  - {gap.format()}")
                parts.append("")
        if self.deps_summary:
            parts.extend(["Dependencies:", self.deps_summary, ""])
        return "\n".join(parts).rstrip()


class DevTools:
    """Unified entry point for static project analysis.

    Bundles import graph, secrets scanning, typing/docstring coverage,
    dependency parsing, and git changelog tools behind one API.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._import_graph: ImportGraph | None = None
        self._secrets: SecretsScanner | None = None
        self._typing: TypingCoverage | None = None
        self._docstrings: DocstringCoverage | None = None
        self._deps: DependencyParser | None = None
        self._changelog: GitChangelog | None = None

    @property
    def imports(self) -> ImportGraph:
        """Lazy-loaded import dependency graph."""
        if self._import_graph is None:
            self._import_graph = ImportGraph(str(self.root))
        return self._import_graph

    @property
    def secrets(self) -> SecretsScanner:
        """Lazy-loaded secrets scanner."""
        if self._secrets is None:
            self._secrets = SecretsScanner(str(self.root))
        return self._secrets

    @property
    def typing(self) -> TypingCoverage:
        """Lazy-loaded typing coverage analyzer."""
        if self._typing is None:
            self._typing = TypingCoverage(str(self.root))
        return self._typing

    @property
    def docstrings(self) -> DocstringCoverage:
        """Lazy-loaded docstring coverage analyzer."""
        if self._docstrings is None:
            self._docstrings = DocstringCoverage(str(self.root))
        return self._docstrings

    @property
    def deps(self) -> DependencyParser:
        """Lazy-loaded dependency parser."""
        if self._deps is None:
            self._deps = DependencyParser(str(self.root))
        return self._deps

    @property
    def changelog(self) -> GitChangelog:
        """Lazy-loaded git changelog generator."""
        if self._changelog is None:
            self._changelog = GitChangelog(str(self.root))
        return self._changelog

    def scan(
        self,
        *,
        imports: bool = True,
        secrets: bool = True,
        typing: bool = True,
        docstrings: bool = True,
        deps: bool = True,
        max_gaps: int = 20,
    ) -> DevToolsReport:
        """Run selected static analyses and return a combined report."""
        report = DevToolsReport(root=str(self.root))

        if imports:
            graph = self.imports
            report.imports_summary = graph.summary()
            report.circular_imports = graph.find_cycles()

        if secrets:
            scanner = self.secrets
            report.secrets_summary = scanner.summary()
            report.secret_findings = scanner.scan()[:max_gaps]

        if typing:
            coverage = self.typing
            report.typing_summary = coverage.summary()
            report.typing_gaps = coverage.analyze()[:max_gaps]

        if docstrings:
            coverage = self.docstrings
            report.docstring_summary = coverage.summary()
            report.docstring_gaps = coverage.analyze()[:max_gaps]

        if deps:
            parser = self.deps
            report.deps_summary = parser.summary()
            report.dependencies = parser.parse()

        return report

    def summary(self) -> str:
        """Run all analyses and return a combined summary."""
        return self.scan().summary()

    def to_context(self) -> str:
        """Run all analyses and return LLM-ready context."""
        return self.scan().to_context()

    def collect_changelog(self, *, max_count: int = 50) -> list[CommitInfo]:
        """Collect recent git commits for changelog generation."""
        return self.changelog.collect(max_count=max_count)

    def format_changelog(
        self,
        commits: list[CommitInfo],
        *,
        version: str = "Unreleased",
    ) -> str:
        """Format commits as Keep a Changelog markdown."""
        return self.changelog.format_markdown(commits, version=version)
