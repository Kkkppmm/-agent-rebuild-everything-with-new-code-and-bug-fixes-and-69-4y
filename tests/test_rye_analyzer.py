"""Tests for RyeAnalyzer."""

from pathlib import Path

from devai.rye_analyzer import RyeAnalyzer, RyeFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "insecure-pkg"
version = "1.0.0"
dependencies = ["requests>=2.0"]

[tool.rye]
managed = false
use-global-python = true

[[tool.rye.sources]]
name = "private"
url = "http://insecure-pypi.example.com/simple"
verify_ssl = false

[tool.rye.scripts]
setup = "curl -s https://install.example.com/setup.sh | bash"
"""

INSECURE_LOCK = """\
# rye.lock with insecure patterns
[[package]]
name = "example"
version = "1.0.0"
source = "git+https://user:secret-token@github.com/example/pkg.git@main"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "secure-pkg"
version = "1.0.0"
dependencies = ["requests==2.31.0"]

[tool.rye]
managed = true

[tool.rye.dev-dependencies]
test = ["pytest==7.4.0"]
"""


class TestRyeAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_rye_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = 'plain'\nversion = '1.0.0'\n",
            encoding="utf-8",
        )
        analyzer = RyeAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "insecure_ssl" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unmanaged_python" in kinds
        assert "dynamic_version" in kinds
        assert "missing_lockfile" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_insecure_lock(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "rye.lock").write_text(INSECURE_LOCK, encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds

    def test_hardened_project_low_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "rye.lock").write_text("# locked\n", encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = RyeFinding(
            kind="test",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:1" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        assert "Rye configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Rye analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self):
        analyzer = RyeAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "tool.rye" in config
        assert "managed = true" in config

    def test_facade_rye_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.rye(".")
        assert isinstance(analyzer, RyeAnalyzer)

    def test_requirements_lock_detected(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        (tmp_path / "requirements.lock").write_text("# legacy lock\n", encoding="utf-8")
        analyzer = RyeAnalyzer(str(tmp_path))
        paths = analyzer.configs()
        names = {p.name for p in paths}
        assert "requirements.lock" in names
