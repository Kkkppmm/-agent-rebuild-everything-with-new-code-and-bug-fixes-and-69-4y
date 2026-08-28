"""Tests for v6.58.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, BuildkiteAnalyzer


class TestV658InfrastructureAnalyzers:
    def test_facade_buildkite(self, tmp_path: Path):
        buildkite_dir = tmp_path / ".buildkite"
        buildkite_dir.mkdir()
        (buildkite_dir / "pipeline.yml").write_text(
            "steps:\n  - label: Tests\n    command: pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().buildkite(tmp_path)
        assert isinstance(analyzer, BuildkiteAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_buildkite_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        buildkite_dir = tmp_path / ".buildkite"
        buildkite_dir.mkdir()
        (buildkite_dir / "pipeline.yml").write_text(
            "steps:\n  - label: Tests\n    command: pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "buildkite" in names
