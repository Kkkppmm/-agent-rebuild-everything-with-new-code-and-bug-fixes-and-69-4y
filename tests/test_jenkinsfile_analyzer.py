"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsfileFinding

INSECURE_JENKINSFILE = """
pipeline {
    agent any
    environment {
        API_SECRET = 'supersecret'
        DEPLOY_TOKEN = "hardcoded-token"
    }
    stages {
        stage('Build') {
            agent {
                docker {
                    image 'nginx:latest'
                    args '-u root'
                    privileged true
                }
            }
            steps {
                sh 'curl -fsSL https://example.com/install.sh | bash'
                sh "echo ${params.USER_INPUT}"
                eval(someVar)
            }
        }
        stage('Deploy') {
            when {
                branch 'master'
            }
            steps {
                withCredentials([password('my-pass', 'plaintext123')]) {
                    sh 'deploy'
                }
            }
        }
    }
}
"""

HARDENED_JENKINSFILE = """
pipeline {
    agent {
        label 'linux'
    }
    options {
        timestamps()
    }
    stages {
        stage('Test') {
            agent {
                docker {
                    image 'python:3.12-slim'
                }
            }
            steps {
                sh 'python -m pytest'
            }
        }
    }
}
"""


class TestJenkinsfileAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_environment" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_docker" in kinds
        assert "unpinned_docker_image" in kinds
        assert "run_as_root" in kinds
        assert "script_injection" in kinds
        assert "eval_usage" in kinds
        assert "hardcoded_credential" in kinds
        assert "agent_any" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.pipelines == 1
        assert analyzer.infos[0].pipeline_type == "declarative"

    def test_finding_format(self):
        finding = JenkinsfileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Jenkinsfile",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "Jenkinsfile:1" in finding.format()

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "pipeline {" in template
        assert "label 'linux'" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Jenkins pipeline analysis:" in context
        assert "health score" in context

    def test_ci_subdirectory(self, tmp_path: Path):
        ci = tmp_path / "ci"
        ci.mkdir()
        (ci / "build.jenkins").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
