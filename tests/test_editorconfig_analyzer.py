"""Tests for EditorConfigAnalyzer."""

from pathlib import Path

from devai.editorconfig_analyzer import EditorConfigAnalyzer, EditorConfigFinding


INSECURE_EDITORCONFIG = """\
root = true

[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 4
api_key = sk-live-hardcoded-secret-token-12345
plugin_url = http://evil.example.com/editorconfig-plugin.js
"""

HARDENED_EDITORCONFIG = """\
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{js,ts,tsx}]
indent_size = 2
"""

MISSING_ROOT_EDITORCONFIG = """\
[*]
charset = utf-8
indent_style = space
indent_size = 4
"""


class TestEditorConfigAnalyzer:
    def test_detects_insecure_editorconfig(self, tmp_path: Path):
        (tmp_path / ".editorconfig").write_text(INSECURE_EDITORCONFIG, encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / ".editorconfig").write_text(HARDENED_EDITORCONFIG, encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_missing_root_flagged(self, tmp_path: Path):
        (tmp_path / ".editorconfig").write_text(MISSING_ROOT_EDITORCONFIG, encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_root" in kinds

    def test_detects_non_utf8_charset(self, tmp_path: Path):
        config = """\
root = true

[*]
charset = latin1
end_of_line = lf
indent_style = space
"""
        (tmp_path / ".editorconfig").write_text(config, encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "non_utf8_charset" in kinds

    def test_detects_nested_root_true(self, tmp_path: Path):
        (tmp_path / ".editorconfig").write_text(HARDENED_EDITORCONFIG, encoding="utf-8")
        nested = tmp_path / "packages" / "app"
        nested.mkdir(parents=True)
        (nested / ".editorconfig").write_text("root = true\n[*]\nindent_size = 2\n", encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "nested_root_true" in kinds

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "EditorConfig: no config files found"

    def test_generate_hardened_template(self):
        config = EditorConfigAnalyzer(".").generate_hardened_template()
        assert "root = true" in config
        assert "charset = utf-8" in config
        assert "end_of_line = lf" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".editorconfig").write_text(INSECURE_EDITORCONFIG, encoding="utf-8")
        analyzer = EditorConfigAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "EditorConfig analysis:" in context
        assert "insecure" in context.lower() or "hardcoded" in context.lower()

    def test_finding_format(self):
        finding = EditorConfigFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".editorconfig",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".editorconfig:1" in finding.format()
