"""Tests for v6.53.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, JenkinsfileAnalyzer


class TestV653InfrastructureAnalyzers:
    def test_facade_jenkins(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(
            "pipeline { agent any; stages {} }\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().jenkins(tmp_path)
        assert isinstance(analyzer, JenkinsfileAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_jenkins_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "Jenkinsfile").write_text(
            "pipeline { agent any; stages {} }\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "jenkins" in names
