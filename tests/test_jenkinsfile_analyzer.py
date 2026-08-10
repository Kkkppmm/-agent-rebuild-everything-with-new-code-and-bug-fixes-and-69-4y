"""Tests for JenkinsfileAnalyzer."""

from pathlib import Path

from devai.jenkinsfile_analyzer import JenkinsfileAnalyzer, JenkinsfileFinding

INSECURE_JENKINSFILE = """
pipeline {
    agent { label 'master' }
    environment {
        API_SECRET = 'supersecret'
    }
    stages {
        stage('Build') {
            steps {
                sh 'curl -fsSL https://example.com/install.sh | bash'
                sh "echo ${params.USER_INPUT}"
                echo "${PASSWORD}"
            }
        }
    }
}
"""

HARDENED_JENKINSFILE = """
pipeline {
    agent { label 'linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
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
    def test_no_jenkinsfile_returns_perfect_score(self, tmp_path: Path):
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
        assert "secret_in_environment" in kinds
        assert "curl_pipe_shell" in kinds
        assert "params_in_shell" in kinds
        assert "credential_echo" in kinds
        assert "master_agent" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_jenkinsfile_scores_well(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.jenkinsfiles == 1
        assert analyzer.infos[0].stages == ["Test"]

    def test_detects_privileged_docker(self, tmp_path: Path):
        content = (
            "pipeline {\n"
            "  agent {\n"
            "    docker {\n"
            "      image 'myapp:latest'\n"
            "      args '-v /var/run/docker.sock:/var/run/docker.sock --privileged'\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        (tmp_path / "Jenkinsfile").write_text(content, encoding="utf-8")
        findings = JenkinsfileAnalyzer(str(tmp_path)).analyze()
        kinds = {f.kind for f in findings}
        assert "latest_tag" in kinds
        assert "docker_sock_mount" in kinds

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Jenkinsfile").write_text(HARDENED_JENKINSFILE, encoding="utf-8")
        analyzer = JenkinsfileAnalyzer(str(tmp_path))
        assert "Jenkinsfiles:" in analyzer.summary()
        assert "pipeline analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "pipeline {" in template
        assert "cleanWs()" in template

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
