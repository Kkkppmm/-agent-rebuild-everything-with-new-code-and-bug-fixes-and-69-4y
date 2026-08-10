"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsfileFinding

INSECURE_JENKINSFILE = """
@Library('shared-lib@master') _
pipeline {
    agent {
        docker {
            image 'node:latest'
            privileged true
            args '-v /:/host'
        }
    }
    environment {
        API_SECRET = 'supersecret'
    }
    stages {
        stage('Install') {
            steps {
                sh 'curl -fsSL https://example.com/install.sh | bash'
                sh "echo ${params.BRANCH}"
                sh 'sudo apt-get update'
            }
        }
    }
}
"""

HARDENED_JENKINSFILE = """
pipeline {
    agent any
    options {
        timestamps()
        disableConcurrentBuilds()
    }
    stages {
        stage('Test') {
            steps {
                sh 'python -m pytest'
            }
        }
    }
}
"""


class TestJenkinsfileAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0
        assert "no pipeline" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "mutable_library" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "param_in_sh" in kinds
        assert "dangerous_sh" in kinds
        assert "privileged_docker" in kinds
        assert "host_mount" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.pipelines == 1
        assert analyzer.infos[0].has_timestamps is True

    def test_finding_format(self):
        finding = JenkinsfileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Jenkinsfile",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert "Jenkinsfile:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "pipeline" in template
        assert "timestamps()" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Jenkins pipeline analysis" in context
        assert "health score" in context
