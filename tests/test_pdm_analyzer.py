"""Tests for PdmAnalyzer."""

from pathlib import Path

from devai.pdm_analyzer import PdmAnalyzer, PdmFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["pdm-backend"]
build-backend = "pdm.backend"

[project]
name = "insecure-pkg"
version = "1.0.0"
dependencies = ["requests>=2.0"]

[tool.pdm]
distribution = true

[[tool.pdm.source]]
name = "private"
url = "http://insecure-pypi.example.com/simple"
verify_ssl = false

[tool.pdm.dev-dependencies]
test = ["pytest>=7.0"]

[tool.pdm.scripts]
setup = "curl -s https://install.example.com/setup.sh | bash"

[tool.pdm.build]
pre_build = "echo building"
"""

INSECURE_PDM_TOML = """\
[repository]
url = "http://pypi.example.com/simple"
username = "admin"
password = "super-secret-password"

[pypi]
token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
"""

INSECURE_LOCK = """\
# pdm.lock with insecure patterns
[[package]]
name = "example"
version = "1.0.0"
summary = "git+https://user:secret-token@github.com/example/pkg.git@main"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["pdm-backend"]
build-backend = "pdm.backend"

[project]
name = "secure-pkg"
version = "1.0.0"
dependencies = ["requests==2.31.0"]

[tool.pdm]
distribution = true

[tool.pdm.dev-dependencies]
test = ["pytest==7.4.0"]
"""


class TestPdmAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_pdm_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = PdmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "insecure_ssl" in kinds
        assert "dangerous_script" in kinds
        assert "missing_lock" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_pdm_toml_issues(self, tmp_path: Path):
        (tmp_path / ".pdm.toml").write_text(INSECURE_PDM_TOML, encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "pypi_token" in kinds

    def test_detects_lock_scm_credentials(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "pdm.lock").write_text(INSECURE_LOCK, encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "pdm.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = PdmFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_sources_and_dependencies(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "pdm.lock").write_text("# lock\n", encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 2
        pyproject_info = next(i for i in analyzer.infos if i.file_kind == "pyproject")
        lock_info = next(i for i in analyzer.infos if i.file_kind == "lock")
        assert pyproject_info.file_kind == "pyproject"
        assert lock_info.file_kind == "lock"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = PdmAnalyzer(str(tmp_path))
        assert "PDM configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "PDM analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = PdmAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "tool.pdm" in config
        assert "PDM_REPO_PASSWORD" in config

    def test_facade_pdm_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.pdm(".")
        assert isinstance(analyzer, PdmAnalyzer)
