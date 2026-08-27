"""Tests for PantsAnalyzer."""

from pathlib import Path

from devai.pants_analyzer import PantsAnalyzer, PantsFinding


INSECURE_PANTS = """\
[GLOBAL]
pants_version = ">=2.20.0"

[pypi]
repos = ["http://insecure-pypi.example.com/simple"]

[docker.registries.bad]
address = "http://registry.example.com"
password = "hardcoded-registry-password"
"""

INSECURE_BUILD = """\
python_sources()

shell_command(
    name="install_tool",
    command="curl -s https://install.example.com/script.sh | bash",
)

docker_image(
    name="privileged",
    privileged=True,
    extra_build_args=["--privileged"],
)

python_requirements(
    name="reqs",
    source="requirements.txt",
)

# secret in assignment
api_key = "sk-live-hardcoded-secret-value"
token = "hardcoded-token-value-for-tests"

pex_binary(
    name="app",
    environment={"API_KEY": "hardcoded-secret", "password": "admin123"},
    entry_point="main.py",
)
"""

HARDENED_PANTS = """\
[GLOBAL]
pants_version = "2.21.0"
backend_packages = ["pants.backend.python"]

[python]
interpreter_constraints = [">=3.10,<3.13"]
"""

HARDENED_BUILD = """\
python_sources()

python_requirements(
    name="reqs",
    source="requirements.txt",
)

docker_image(
    name="app",
    repository="registry.example.com/app",
)
"""


class TestPantsAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_pants_toml(self, tmp_path: Path):
        (tmp_path / "pants.toml").write_text(INSECURE_PANTS, encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "unpinned_pants_version" in kinds
        assert analyzer.health_score() < 60.0

    def test_detects_insecure_build(self, tmp_path: Path):
        (tmp_path / "BUILD").write_text(INSECURE_BUILD, encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "environment_secret" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pants.toml").write_text(HARDENED_PANTS, encoding="utf-8")
        (tmp_path / "BUILD").write_text(HARDENED_BUILD, encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "BUILD").write_text(INSECURE_BUILD, encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, PantsFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "BUILD").write_text(INSECURE_BUILD, encoding="utf-8")
        analyzer = PantsAnalyzer(str(tmp_path))
        assert "Pants configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Pants analysis:" in context
        assert "targets:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = PantsAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "pants_version" in config
        assert "backend_packages" in config
