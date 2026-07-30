"""DevTools — unified facade for static project analysis."""

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
    """Combined static analysis report for a project."""

    root: str
    imports: str = ""
    secrets: str = ""
    typing: str = ""
    docstrings: str = ""
    dependencies: str = ""
    changelog: str = ""
    import_cycles: list[list[str]] = field(default_factory=list)
    secret_findings: list[SecretFinding] = field(default_factory=list)
    typing_gaps: list[TypingGap] = field(default_factory=list)
    docstring_gaps: list[DocstringGap] = field(default_factory=list)
    dependencies_list: list[Dependency] = field(default_factory=list)

    def summary(self) -> str:
        """Return a combined human-readable summary."""
        sections = [
            f"DevTools report for {self.root}",
            "",
            "== Imports ==",
            self.imports or "(not analyzed)",
            "",
            "== Secrets ==",
            self.secrets or "(not analyzed)",
            "",
            "== Typing ==",
            self.typing or "(not analyzed)",
            "",
            "== Docstrings ==",
            self.docstrings or "(not analyzed)",
            "",
            "== Dependencies ==",
            self.dependencies or "(not analyzed)",
        ]
        if self.import_cycles:
            sections.extend(["", "== Circular Imports =="])
            for cycle in self.import_cycles[:5]:
                sections.append(" -> ".join(cycle))
        return "\n".join(sections)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context from all analyzed sections."""
        lines = [
            f"Static analysis for project: {self.root}",
            "",
            self.imports,
            "",
            self.secrets,
            "",
            self.typing,
            "",
            self.docstrings,
            "",
            self.dependencies,
        ]
        if self.import_cycles:
            lines.extend(["", "Circular imports detected:"])
            for cycle in self.import_cycles[:limit]:
                lines.append(" -> ".join(cycle))
        return "\n".join(lines)


class DevTools:
    """Unified facade for static project analysis.

    Wraps import graph, secrets scanning, typing coverage, docstring
    coverage, dependency parsing, and git changelog utilities.

    Example::

        from devai import DevTools

        tools = DevTools(".")
        print(tools.summary())
        report = tools.analyze_all()
        print(report.to_context())
    """

    def __init__(
        self,
        root: str | Path,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.ignore_dirs = ignore_dirs
        self._import_graph: ImportGraph | None = None
        self._secrets: SecretsScanner | None = None
        self._typing: TypingCoverage | None = None
        self._docstrings: DocstringCoverage | None = None
        self._deps: DependencyParser | None = None
        self._changelog: GitChangelog | None = None

    @property
    def imports(self) -> ImportGraph:
        """Lazy-loaded import graph analyzer."""
        if self._import_graph is None:
            self._import_graph = ImportGraph(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
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
            self._typing = TypingCoverage(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._typing

    @property
    def docstrings(self) -> DocstringCoverage:
        """Lazy-loaded docstring coverage analyzer."""
        if self._docstrings is None:
            self._docstrings = DocstringCoverage(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._docstrings

    @property
    def dependencies(self) -> DependencyParser:
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

    def summary(self) -> str:
        """Return a quick combined summary without full deep analysis."""
        return self.analyze_all().summary()

    def analyze_all(self) -> DevToolsReport:
        """Run all static analyzers and return a combined report."""
        import_graph = self.imports
        import_graph.build()
        cycles = import_graph.find_cycles()

        secrets = self.secrets
        secrets.scan()

        typing = self.typing
        typing_gaps = typing.analyze()

        docstrings = self.docstrings
        docstring_gaps = docstrings.analyze()

        deps = self.dependencies
        dep_list = deps.parse()

        return DevToolsReport(
            root=str(self.root),
            imports=import_graph.summary(),
            secrets=secrets.summary(),
            typing=typing.summary(),
            docstrings=docstrings.summary(),
            dependencies=deps.summary(),
            import_cycles=cycles,
            secret_findings=secrets.findings,
            typing_gaps=typing_gaps,
            docstring_gaps=docstring_gaps,
            dependencies_list=dep_list,
        )

    def collect_changelog(
        self,
        *,
        max_count: int = 50,
        version: str = "Unreleased",
    ) -> str:
        """Generate Keep a Changelog-style markdown from git history."""
        commits = self.changelog.collect(max_count=max_count)
        return self.changelog.format_markdown(commits, version=version)

    def find_cycles(self) -> list[list[str]]:
        """Find circular import chains in the project."""
        self.imports.build()
        return self.imports.find_cycles()

    def scan_secrets(self) -> list[SecretFinding]:
        """Scan for hardcoded secrets and return findings."""
        return self.secrets.scan()

    def typing_stats(self) -> TypingStats:
        """Return typing coverage statistics."""
        self.typing.analyze()
        return self.typing.stats

    def docstring_stats(self) -> DocstringStats:
        """Return docstring coverage statistics."""
        self.docstrings.analyze()
        return self.docstrings.stats

    def list_dependencies(self) -> list[Dependency]:
        """Parse and return project dependencies."""
        return self.dependencies.parse()

    def import_edges(self) -> list[ImportEdge]:
        """Return all import edges in the project."""
        self.imports.build()
        return self.imports.edges

    def recent_commits(self, max_count: int = 20) -> list[CommitInfo]:
        """Collect recent git commits."""
        return self.changelog.collect(max_count=max_count)
