"""Tests for v6.54.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, GitLabCIAnalyzer


class TestV654InfrastructureAnalyzers:
    def test_facade_gitlab_ci(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages: [test]\ntest:\n  script: echo ok\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().gitlab_ci(tmp_path)
        assert isinstance(analyzer, GitLabCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_gitlab_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages: [test]\ntest:\n  script: echo ok\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "gitlab_ci" in names
