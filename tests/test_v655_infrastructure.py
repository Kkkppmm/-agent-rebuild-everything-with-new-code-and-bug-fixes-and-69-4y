"""Tests for v6.55.0 infrastructure analyzers."""

from pathlib import Path

from devai import BitbucketPipelinesAnalyzer, CircleCIAnalyzer, DevAI


class TestV655InfrastructureAnalyzers:
    def test_facade_circleci(self, tmp_path: Path):
        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(
            "version: 2.1\njobs:\n  test:\n    docker:\n      - image: cimg/python:3.12\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().circleci(tmp_path)
        assert isinstance(analyzer, CircleCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_facade_bitbucket_pipelines(self, tmp_path: Path):
        (tmp_path / "bitbucket-pipelines.yml").write_text(
            "pipelines:\n  default:\n    - step:\n        script:\n          - echo ok\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().bitbucket_pipelines(tmp_path)
        assert isinstance(analyzer, BitbucketPipelinesAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_new_categories(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        config_dir = tmp_path / ".circleci"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text("version: 2.1\n", encoding="utf-8")
        (tmp_path / "bitbucket-pipelines.yml").write_text("pipelines: {}\n", encoding="utf-8")

        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "circleci" in names
        assert "bitbucket_pipelines" in names
