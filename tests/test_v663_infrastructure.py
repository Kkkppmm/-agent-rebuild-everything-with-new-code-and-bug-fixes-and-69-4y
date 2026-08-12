"""Tests for v6.63.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, ConcourseCIAnalyzer


class TestV663InfrastructureAnalyzers:
    def test_facade_concourse_ci(self, tmp_path: Path):
        ci_dir = tmp_path / "ci"
        ci_dir.mkdir()
        (ci_dir / "pipeline.yml").write_text(
            "resources:\n"
            "  - name: repo\n"
            "    type: git\n"
            "    source:\n"
            "      uri: ((git-uri))\n"
            "jobs:\n"
            "  - name: test\n"
            "    plan:\n"
            "      - get: repo\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().concourse_ci(tmp_path)
        assert isinstance(analyzer, ConcourseCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_concourse_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        ci_dir = tmp_path / "ci"
        ci_dir.mkdir()
        (ci_dir / "pipeline.yml").write_text(
            "resources:\n"
            "  - name: repo\n"
            "    type: git\n"
            "    source:\n"
            "      uri: ((git-uri))\n"
            "jobs:\n"
            "  - name: test\n"
            "    plan:\n"
            "      - get: repo\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "concourse_ci" in names
