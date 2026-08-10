"""Tests for JenkinsAnalyzer."""

from pathlib import Path

from devai.jenkins_analyzer import JenkinsAnalyzer, JenkinsFinding

INSECURE_JENKINSFILE = """
pipeline {
    agent { label 'master' }
    environment {
        API_SECRET = 'supersecret'
        TOKEN = 'abc123'
    }
    stages {
        stage('Build') {
            steps {
                sh 'curl -fsSL https://example.com/install.sh | bash'
                sh 'sudo pip install -r requirements.txt'
            }
        }
        stage('Deploy') {
            agent {
                docker {
                    image 'python'
                    args '--privileged --user root'
                }
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'deploy', password: 'plaintext', usernameVariable: 'U', passwordVariable: 'P')]) {
                    sh 'deploy.sh'
                }
            }
        }
    }
}
"""

HARDENED_JENKINSFILE = """
pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '-u 1000:1000'
        }
    }
    options {
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
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


class TestJenkinsAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JenkinsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "master_node" in kinds
        assert "privileged_docker" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert analyzer.infos[0].uses_docker is True

    def test_finds_jenkinsfile_groovy(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile.groovy").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_generate_template(self, tmp_path: Path):
        analyzer = JenkinsAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "buildDiscarder" in template
        assert "credentials" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Jenkins pipeline analysis" in context

    def test_finding_format(self):
        finding = JenkinsFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Jenkinsfile",
            lineno=1,
        )
        assert "high" in finding.format()
