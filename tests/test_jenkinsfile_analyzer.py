"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsFinding


INSECURE_PIPELINE = """
pipeline {
    agent any
    environment {
        API_TOKEN = "sk-live-hardcoded-secret"
    }
    stages {
        stage('Setup') {
            steps {
                sh 'curl -sSL http://install.example.com/setup.sh | bash'
                sh "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine"
                sh "echo Deploying ${params.BRANCH}"
                echo credentials('my-secret')
            }
        }
        stage('Deploy') {
            steps {
                sh 'sudo systemctl restart app'
            }
        }
        stage('Approve') {
            steps {
                input message: 'Deploy to production?'
            }
        }
    }
}
"""

HARDENED_PIPELINE = """
pipeline {
    agent { label 'linux' }

    options {
        timeout(time: 20, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        DEPLOY_KEY = credentials('deploy-key')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                sh 'make test'
            }
        }
    }
}
"""


def _write_jenkinsfile(tmp_path: Path, content: str, name: str = "Jenkinsfile") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestJenkinsfileAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pipeline(self, tmp_path: Path):
        _write_jenkinsfile(tmp_path, INSECURE_PIPELINE)
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_docker" in kinds
        assert "docker_socket_mount" in kinds
        assert "groovy_injection" in kinds
        assert "credential_exposure" in kinds
        assert "sudo_in_shell" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_few_findings(self, tmp_path: Path):
        _write_jenkinsfile(tmp_path, HARDENED_PIPELINE)
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_finds_jenkinsfile_variants(self, tmp_path: Path):
        ci_dir = tmp_path / "jenkins"
        ci_dir.mkdir()
        (ci_dir / "deploy.groovy").write_text("pipeline { agent any }\n", encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_summary_and_context(self, tmp_path: Path):
        _write_jenkinsfile(tmp_path, INSECURE_PIPELINE)
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert "Jenkins pipelines:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Jenkins pipeline analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_snippet(self):
        snippet = JenkinsfileAnalyzer(".").generate_hardened_pipeline_snippet()
        assert "disableConcurrentBuilds" in snippet
        assert "credentials(" in snippet

    def test_finding_format(self):
        finding = JenkinsFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Jenkinsfile",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "Jenkinsfile:1" in finding.format()
