"""Tests for PipAnalyzer."""

from pathlib import Path

from devai.pip_analyzer import PipAnalyzer, PipFinding


INSECURE_REQUIREMENTS = """\
--index-url http://insecure-pypi.example.com/simple/
--trusted-host insecure-pypi.example.com
requests>=2.0
flask
git+https://user:secret-token@github.com/example/bad-lib.git@main#egg=bad-lib
curl -s https://install.example.com/script.sh | bash
"""

INSECURE_PIP_CONF = """\
[global]
index-url = http://mirror.example.com/simple/
extra-index-url = https://deploy:pypi-hardcoded-password@private.pypi.example/simple/
trusted-host = mirror.example.com
cert = false
password = hardcoded-pypi-password
"""

HARDENED_REQUIREMENTS = """\
requests==2.31.0
flask==3.0.0
"""

HARDENED_CONSTRAINTS = """\
requests==2.31.0
flask==3.0.0
"""


class TestPipAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_requirements_suffix(self, tmp_path: Path):
        (tmp_path / "requirements-dev.txt").write_text(HARDENED_REQUIREMENTS, encoding="utf-8")
        (tmp_path / "constraints-dev.txt").write_text(HARDENED_CONSTRAINTS, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        assert analyzer.stats.configs >= 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(INSECURE_REQUIREMENTS, encoding="utf-8")
        (tmp_path / "pip.conf").write_text(INSECURE_PIP_CONF, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds
        assert "insecure_ssl" in kinds
        assert "dynamic_version" in kinds
        assert "unpinned_git_dep" in kinds
        assert "trusted_host" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(HARDENED_REQUIREMENTS, encoding="utf-8")
        (tmp_path / "constraints.txt").write_text(HARDENED_CONSTRAINTS, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(INSECURE_REQUIREMENTS, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, PipFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(INSECURE_REQUIREMENTS, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        assert "Pip configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Pip analysis:" in context
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = PipAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "pip.conf" in config
        assert "constraints.txt" in config

    def test_detects_missing_constraints(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text(HARDENED_REQUIREMENTS, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "missing_constraints" in kinds

    def test_pip_ini_config(self, tmp_path: Path):
        (tmp_path / "pip.ini").write_text(INSECURE_PIP_CONF, encoding="utf-8")
        analyzer = PipAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
