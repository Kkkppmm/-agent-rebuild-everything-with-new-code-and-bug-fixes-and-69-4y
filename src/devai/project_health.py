"""ProjectHealth — unified project health dashboard for developers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from devai.code_metrics import CodeMetrics
from devai.deps_parser import DependencyParser
from devai.docstring_coverage import DocstringCoverage
from devai.project import DEFAULT_IGNORE_DIRS
from devai.secrets import SecretsScanner
from devai.test_mapper import TestMapper
from devai.typing_coverage import TypingCoverage


@dataclass
class HealthCategory:
    """Score and summary for one health dimension."""

    name: str
    score: float
    summary: str
    details: dict = field(default_factory=dict)


@dataclass
class ProjectHealthReport:
    """Aggregate project health report."""

    root: str
    overall_score: float
    categories: list[HealthCategory] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Project health: {self.overall_score:.0f}/100",
            f"Root: {self.root}",
            "",
        ]
        for cat in self.categories:
            lines.append(f"  {cat.name}: {cat.score:.0f}/100 — {cat.summary}")
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export as a JSON-serializable dict."""
        return {
            "root": self.root,
            "overall_score": self.overall_score,
            "categories": [
                {
                    "name": c.name,
                    "score": c.score,
                    "summary": c.summary,
                    "details": c.details,
                }
                for c in self.categories
            ],
            "recommendations": self.recommendations,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Export as a Markdown report."""
        lines = [
            "# Project Health Report",
            "",
            f"**Overall score:** {self.overall_score:.0f}/100",
            f"**Root:** `{self.root}`",
            "",
            "## Categories",
            "",
            "| Category | Score | Summary |",
            "|----------|-------|---------|",
        ]
        for cat in self.categories:
            safe_summary = cat.summary.replace("|", "\\|")
            lines.append(f"| {cat.name} | {cat.score:.0f} | {safe_summary} |")
        if self.recommendations:
            lines.extend(["", "## Recommendations", ""])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
        return "\n".join(lines)


class ProjectHealth:
    """Run static analysis across a project and produce a unified health report.

    Combines code metrics, typing coverage, docstring coverage, test mapping,
    dependency hygiene, and secrets scanning into a single developer dashboard.
    """

    WEIGHTS = {
        "metrics": 0.15,
        "typing": 0.20,
        "docstrings": 0.15,
        "tests": 0.25,
        "dependencies": 0.10,
        "secrets": 0.15,
    }

    def __init__(
        self,
        root: str,
        *,
        source_dir: str = "src",
        test_dir: str = "tests",
        complexity_threshold: int = 10,
        ignore_dirs: set[str] | None = None,
        scan_secrets: bool = True,
    ) -> None:
        self.root = Path(root)
        self.source_dir = source_dir
        self.test_dir = test_dir
        self.complexity_threshold = complexity_threshold
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.scan_secrets = scan_secrets
        self._report: ProjectHealthReport | None = None

    def _score_complexity(self, metrics: CodeMetrics) -> tuple[float, str, dict]:
        metrics.analyze()
        project = metrics.project
        high = metrics.high_complexity()
        if project.total_functions == 0:
            return 100.0, "No functions to analyze", {"high_complexity": 0}

        ratio = len(high) / project.total_functions
        score = max(0.0, 100.0 - ratio * 200.0)
        summary = (
            f"avg complexity {project.avg_complexity}, "
            f"{len(high)} high-complexity functions"
        )
        return round(score, 1), summary, {
            "avg_complexity": project.avg_complexity,
            "max_complexity": project.max_complexity,
            "high_complexity_count": len(high),
            "total_functions": project.total_functions,
            "total_sloc": project.total_sloc,
        }

    def _score_typing(self, typing: TypingCoverage) -> tuple[float, str, dict]:
        typing.analyze()
        pct = typing.coverage_pct()
        stats = typing.stats
        summary = f"{pct}% fully typed ({stats.fully_typed}/{stats.total_functions})"
        return pct, summary, {
            "coverage_pct": pct,
            "fully_typed": stats.fully_typed,
            "partially_typed": stats.partially_typed,
            "untyped": stats.untyped,
            "gaps": len(typing._gaps),
        }

    def _score_docstrings(self, docstrings: DocstringCoverage) -> tuple[float, str, dict]:
        docstrings.analyze()
        pct = docstrings.coverage_pct()
        stats = docstrings.stats
        summary = f"{pct}% documented ({stats.documented}/{stats.total_items})"
        return pct, summary, {
            "coverage_pct": pct,
            "documented": stats.documented,
            "undocumented": stats.undocumented,
            "gaps": len(docstrings._gaps),
        }

    def _score_tests(self, mapper: TestMapper) -> tuple[float, str, dict]:
        report = mapper.map()
        pct = report.coverage_pct
        summary = f"{pct}% modules have tests ({report.tested}/{report.total_modules})"
        return pct, summary, {
            "coverage_pct": pct,
            "tested": report.tested,
            "total_modules": report.total_modules,
            "untested_count": len(report.untested),
        }

    def _score_dependencies(self, deps: DependencyParser) -> tuple[float, str, dict]:
        all_deps = deps.parse()
        if not all_deps:
            return 100.0, "No dependencies declared", {"total": 0}

        unpinned = deps.unpinned()
        dupes = deps.duplicates()
        unpinned_ratio = len(unpinned) / len(all_deps)
        dupe_penalty = min(30.0, len(dupes) * 10.0)
        score = max(0.0, 100.0 - unpinned_ratio * 70.0 - dupe_penalty)
        summary = f"{len(all_deps)} deps, {len(unpinned)} unpinned, {len(dupes)} duplicates"
        return round(score, 1), summary, {
            "total": len(all_deps),
            "unpinned": len(unpinned),
            "duplicates": len(dupes),
        }

    def _score_secrets(self, scanner: SecretsScanner) -> tuple[float, str, dict]:
        findings = scanner.scan()
        if not findings:
            return 100.0, "No potential secrets found", {"findings": 0}
        high = sum(1 for f in findings if f.confidence == "high")
        penalty = min(100.0, len(findings) * 15.0 + high * 10.0)
        score = max(0.0, 100.0 - penalty)
        summary = f"{len(findings)} potential secrets ({high} high confidence)"
        return round(score, 1), summary, {
            "findings": len(findings),
            "high_confidence": high,
        }

    def _build_recommendations(self, categories: list[HealthCategory]) -> list[str]:
        recs: list[str] = []
        for cat in categories:
            if cat.name == "typing" and cat.score < 80:
                recs.append("Add type hints to untyped functions to improve maintainability")
            elif cat.name == "docstrings" and cat.score < 70:
                recs.append("Document public functions, methods, and classes with docstrings")
            elif cat.name == "tests" and cat.score < 60:
                untested = cat.details.get("untested_count", 0)
                if untested:
                    recs.append(f"Add tests for {untested} untested module(s)")
            elif cat.name == "metrics" and cat.details.get("high_complexity_count", 0) > 0:
                recs.append(
                    "Refactor high-complexity functions to reduce cyclomatic complexity"
                )
            elif cat.name == "dependencies" and cat.details.get("unpinned", 0) > 0:
                recs.append("Pin unpinned dependencies with exact versions for reproducibility")
            elif cat.name == "secrets" and cat.details.get("findings", 0) > 0:
                recs.append("Review and remove hardcoded secrets; use environment variables")
        return recs

    def analyze(self) -> ProjectHealthReport:
        """Run all analyzers and return a unified health report."""
        if self._report is not None:
            return self._report

        root_str = str(self.root)
        categories: list[HealthCategory] = []

        metrics = CodeMetrics(
            root_str,
            complexity_threshold=self.complexity_threshold,
            ignore_dirs=self.ignore_dirs,
        )
        score, summary, details = self._score_complexity(metrics)
        categories.append(HealthCategory("metrics", score, summary, details))

        typing = TypingCoverage(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_typing(typing)
        categories.append(HealthCategory("typing", score, summary, details))

        docstrings = DocstringCoverage(root_str, ignore_dirs=self.ignore_dirs)
        score, summary, details = self._score_docstrings(docstrings)
        categories.append(HealthCategory("docstrings", score, summary, details))

        mapper = TestMapper(
            root_str,
            source_dir=self.source_dir,
            test_dir=self.test_dir,
            ignore_dirs=self.ignore_dirs,
        )
        score, summary, details = self._score_tests(mapper)
        categories.append(HealthCategory("tests", score, summary, details))

        deps = DependencyParser(root_str)
        score, summary, details = self._score_dependencies(deps)
        categories.append(HealthCategory("dependencies", score, summary, details))

        if self.scan_secrets:
            scanner = SecretsScanner(root_str, ignore_dirs=self.ignore_dirs)
            score, summary, details = self._score_secrets(scanner)
            categories.append(HealthCategory("secrets", score, summary, details))

        overall = 0.0
        weight_sum = 0.0
        for cat in categories:
            weight = self.WEIGHTS.get(cat.name, 0.1)
            overall += cat.score * weight
            weight_sum += weight
        overall_score = round(overall / weight_sum if weight_sum else 0.0, 1)

        recommendations = self._build_recommendations(categories)
        self._report = ProjectHealthReport(
            root=root_str,
            overall_score=overall_score,
            categories=categories,
            recommendations=recommendations,
        )
        return self._report

    @property
    def report(self) -> ProjectHealthReport:
        """Return the health report (runs analysis on first access)."""
        if self._report is None:
            self.analyze()
        return self._report

    def summary(self) -> str:
        """Return a human-readable summary."""
        return self.report.summary()

    def to_context(self) -> str:
        """Build LLM-ready context describing project health."""
        report = self.analyze()
        lines = [
            "Project health analysis:",
            report.summary(),
            "",
            "Category details:",
        ]
        for cat in report.categories:
            lines.append(f"  [{cat.name}] {cat.score:.0f}/100")
            for key, value in cat.details.items():
                lines.append(f"    {key}: {value}")
        return "\n".join(lines)
