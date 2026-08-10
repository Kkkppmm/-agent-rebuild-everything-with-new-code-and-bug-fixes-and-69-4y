"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsfileFinding

INSECURE_JENKINSFILE = """
@Library('shared-lib@main') _

pipeline {
    agent any
    environment {
        API_SECRET = 'supersecret'
    }
    stages {
        stage('Build') {
            agent {
                docker {
                    image 'node:latest'
                    args '--privileged'
                }
            }
            steps {
                sh 'curl -fsSL http://example.com/install.sh | bash'
                sh "echo ${params.USER_INPUT}"
                sh 'sudo apt-get update'
            }
        }
        stage('Deploy') {
            steps {
                input message: 'Deploy to production?'
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
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
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
        assert "unpinned_library" in kinds
        assert "agent_any" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "script_injection" in kinds
        assert "sudo_in_shell" in kinds
        assert "privileged_docker" in kinds
        assert "docker_latest_tag" in kinds
        assert "http_download" in kinds
        assert "unrestricted_input" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_jenkinsfile_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.jenkinsfiles == 1
        assert analyzer.infos[0].is_declarative is True
        assert len(analyzer.infos[0].stages) >= 2

    def test_detects_jenkinsfile_variants(self, tmp_path: Path):
        ci_dir = tmp_path / "ci"
        ci_dir.mkdir()
        (ci_dir / "Jenkinsfile.groovy").write_text("pipeline { agent any }", encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert analyzer.stats.jenkinsfiles == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert "Jenkinsfiles:" in analyzer.summary()
        assert "pipeline analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "disableConcurrentBuilds()" in template
        assert "timeout(" in template

    def test_finding_format(self):
        finding = JenkinsfileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test message",
            path="Jenkinsfile",
            lineno=10,
            line="sh 'curl | bash'",
        )
        assert "[high]" in finding.format()
        assert "Jenkinsfile:10" in finding.format()
