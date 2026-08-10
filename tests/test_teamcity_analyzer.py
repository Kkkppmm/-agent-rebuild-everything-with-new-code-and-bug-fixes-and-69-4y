"""Tests for TeamCityAnalyzer."""

from pathlib import Path

from devai.teamcity_analyzer import TeamCityAnalyzer, TeamCityFinding


INSECURE_CONFIG = '''
import jetbrains.buildServer.configs.kotlin.*

version = "2024.03"

project {
    vcsRoot(HttpsGitVcsRoot {
        id("Repo")
        name = "App"
        url = "http://git.example.com/app.git"
        authMethod = password {
            userName = "ci"
            password = "super-secret-password"
        }
    })

    buildType(BuildType {
        id("Build")
        name = "Build"
        vcs {
            root(HttpsGitVcsRoot { id("Repo") })
            branchFilter = "*"
        }
        steps {
            script {
                name = "Setup"
                scriptContent = "curl -sSL http://install.example.com/setup.sh | bash; echo %teamcity.build.branch%"
            }
            script {
                name = "Deploy"
                scriptContent = "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock -u root golang:latest"
            }
        }
        params {
            param("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz1234567890", display = ParameterDisplay.NORMAL)
        }
    })

    buildType(BuildType {
        id("SecurityAudit")
        name = "Security Audit"
        enabled = false
    })
}
'''

HARDENED_CONFIG = '''
import jetbrains.buildServer.configs.kotlin.*

version = "2024.03"

project {
    vcsRoot(HttpsGitVcsRoot {
        id("Repo")
        name = "App"
        url = "https://github.com/example/app.git"
        authMethod = password {
            userName = "ci-bot"
            password = "credentialsJSON:git-token"
        }
    })

    buildType(BuildType {
        id("Tests")
        name = "Tests"
        vcs {
            root(HttpsGitVcsRoot { id("Repo") })
            branchFilter = "+:main"
        }
        steps {
            script {
                name = "Run tests"
                scriptContent = "python -m pytest"
            }
        }
        triggers {
            vcs {
                branchFilter = "+:main"
            }
        }
    })
}
'''


class TestTeamCityAnalyzer:
    def test_no_teamcity_files(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        analyzer = TeamCityAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_finds_teamcity_settings(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = TeamCityAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_insecure_vs_hardened(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(INSECURE_CONFIG, encoding="utf-8")

        insecure = TeamCityAnalyzer(str(tmp_path))
        insecure_score = insecure.health_score()
        insecure_findings = insecure.analyze()

        (tc_dir / "settings.kts").write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = TeamCityAnalyzer(str(tmp_path))
        hardened_score = hardened.health_score()

        assert len(insecure_findings) > 0
        assert insecure_score < hardened_score

    def test_finding_types(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(INSECURE_CONFIG, encoding="utf-8")
        findings = TeamCityAnalyzer(str(tmp_path)).analyze()
        kinds = {f.kind for f in findings}
        assert all(isinstance(f, TeamCityFinding) for f in findings)
        assert "hardcoded_secret" in kinds or "vcs_password" in kinds
        assert "curl_pipe_shell" in kinds
        assert "broad_vcs_trigger" in kinds

    def test_generate_template(self, tmp_path: Path):
        analyzer = TeamCityAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "TeamCityAnalyzer" in template
        assert "buildType" in template
        assert "credentialsJSON" in template

    def test_summary_and_context(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TeamCityAnalyzer(str(tmp_path))
        assert "TeamCity:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_finding_format(self, tmp_path: Path):
        tc_dir = tmp_path / ".teamcity"
        tc_dir.mkdir()
        (tc_dir / "settings.kts").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TeamCityAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert finding.format().startswith("[")
