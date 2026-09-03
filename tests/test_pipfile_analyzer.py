"""Tests for PipfileAnalyzer."""

from pathlib import Path

from devai.pipfile_analyzer import PipfileAnalyzer, PipfileFinding


INSECURE_PIPFILE = """\
[[source]]
url = "http://insecure-pypi.example.com/simple"
verify_ssl = false
name = "private"

[packages]
requests = "*"
bad-lib = {git = "https://user:secret-token@github.com/example/bad-lib.git", ref = "main"}

[dev-packages]
pytest = ">=0"

[scripts]
install-deps = "sh -c 'curl -s https://install.example.com/script.sh | bash'"
"""

INSECURE_LOCK = """\
{
    "_meta": {
        "hash": {"sha256": "abc123"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.10"}
    },
    "default": {
        "requests": {
            "hashes": ["sha256:abc"],
            "index": "pypi",
            "version": "==2.31.0"
        }
    },
    "develop": {},
    "sources": [
        {"url": "http://mirror.example.com/simple", "verify_ssl": false, "name": "pypi"}
    ]
}
"""

HARDENED_PIPFILE = """\
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.31.0"

[requires]
python_version = "3.10"
"""


class TestPipfileAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_pipfile_toml(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = PipfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text(INSECURE_PIPFILE, encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "insecure_ssl" in kinds
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "curl_pipe_shell" in kinds
        assert "missing_lockfile" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_lockfile_issues(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text(HARDENED_PIPFILE, encoding="utf-8")
        (tmp_path / "Pipfile.lock").write_text(INSECURE_LOCK, encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "insecure_ssl" in kinds
        assert "missing_lockfile" not in kinds

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text(HARDENED_PIPFILE, encoding="utf-8")
        (tmp_path / "Pipfile.lock").write_text('{"default": {}, "develop": {}}\n', encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = PipfileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Pipfile",
            lineno=1,
            line="test = 1",
        )
        assert "[high]" in finding.format()
        assert "Pipfile:1" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text(INSECURE_PIPFILE, encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        assert "Pipenv configs:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Pipenv analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = PipfileAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "verify_ssl = true" in config
        assert "pypi.org" in config

    def test_infos_track_dependencies_and_sources(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text(HARDENED_PIPFILE, encoding="utf-8")
        (tmp_path / "Pipfile.lock").write_text('{"default": {}, "develop": {}}\n', encoding="utf-8")
        analyzer = PipfileAnalyzer(str(tmp_path))
        analyzer.analyze()
        pipfile_info = next(i for i in analyzer.infos if i.file_kind == "pipfile")
        assert "requests" in pipfile_info.dependencies
        assert any("pypi.org" in s for s in pipfile_info.sources)
