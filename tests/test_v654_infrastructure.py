"""Tests for v6.54.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, JenkinsfileAnalyzer


class TestV654InfrastructureAnalyzers:
    def test_facade_jenkinsfile(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(
            "pipeline {\n  agent any\n  stages {\n"
            "    stage('Build') { steps { sh 'echo hello' } }\n  }\n}\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().jenkinsfile(tmp_path)
        assert isinstance(analyzer, JenkinsfileAnalyzer)
        assert analyzer.stats.jenkinsfiles == 1

    def test_project_health_includes_jenkinsfile_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "Jenkinsfile").write_text(
            "pipeline {\n  agent any\n  stages {\n"
            "    stage('Build') { steps { sh 'echo hello' } }\n  }\n}\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "jenkinsfile" in names
