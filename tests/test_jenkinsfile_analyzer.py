"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsfileFinding


INSECURE_JENKINSFILE = """
@Library('shared-lib@main') _

pipeline {
    agent any

    options {
        disableConcurrentBuilds(false)
        skipDefaultCheckout()
    }

    environment {
        API_SECRET = 'hardcoded-secret-value'
        password = "plaintext-pass"
    }

    stages {
        stage('Install') {
            steps {
                sh 'curl -fsSL http://example.com/install.sh | bash'
                sh 'curl -k https://insecure.example.com/setup.sh'
                sh 'sudo apt-get install -y build-essential'
                sh 'docker run --privileged -v /:/host ubuntu bash'
            }
        }
        stage('Deploy') {
            steps {
                writeFile file: 'secret.pem', text: credentials('deploy-key')
                archiveArtifacts artifacts: '**/*.pem, credentials.txt'
            }
        }
    }
}
"""

HARDENED_JENKINSFILE = """
@Library('shared-pipeline@v1.2.3') _

pipeline {
    agent {
        label 'linux'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Test') {
            steps {
                sh 'python -m pytest'
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
"""


class TestJenkinsfileAnalyzer:
    def test_no_jenkinsfiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(INSECURE_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "secret_in_environment" in kinds
        assert "plain_text_password" in kinds
        assert "insecure_tls" in kinds
        assert "sudo_in_shell" in kinds
        assert "privileged_docker" in kinds
        assert "unpinned_library" in kinds
        assert "agent_any" in kinds
        assert "skip_default_checkout" in kinds
        assert "writefile_secret" in kinds
        assert "archive_credentials" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_jenkinsfile_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.jenkinsfiles == 1
        assert analyzer.infos[0].declarative is True
        assert "Checkout" in analyzer.infos[0].stages

    def test_finds_jenkinsfiles_in_subdirectory(self, tmp_path: Path):
        jenkins_dir = tmp_path / "jenkins"
        jenkins_dir.mkdir()
        (jenkins_dir / "ci.groovy").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 1

    def test_jenkinsfile_variant_name(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile.prod").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert "Jenkinsfiles:" in analyzer.summary()
        assert "Jenkinsfile analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "pipeline {" in template
        assert "disableConcurrentBuilds()" in template

    def test_finding_format(self):
        finding = JenkinsfileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="unsafe",
            path="Jenkinsfile",
            lineno=2,
        )
        assert "Jenkinsfile:2" in finding.format()
