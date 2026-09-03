"""Tests for ZolaAnalyzer."""

from pathlib import Path

from devai.zola_analyzer import ZolaAnalyzer, ZolaFinding


INSECURE_ZOLA = """\
base_url = "http://insecure.example.com"
title = "Demo Docs"
default_language = "en"
compile_sass = true
api_key = "sk-hardcoded-secret"

theme = "https://cdn.example.com/theme.zip"

[markdown]
external_links_target_blank = true
render_emoji = true

[search]
include_content = true

[server]
interface = "0.0.0.0"

slugify = "off"

eval("print('bad')")
"""

HARDENED_ZOLA = """\
base_url = "https://example.com"
title = "Demo Docs"
default_language = "en"
compile_sass = true
generate_feeds = true

[markdown]
external_links_target_blank = false
render_emoji = false

[search]
include_content = false

[server]
interface = "127.0.0.1"
"""


class TestZolaAnalyzer:
    def test_detects_insecure_zola_config(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(INSECURE_ZOLA, encoding="utf-8")
        analyzer = ZolaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "bind_all_interfaces" in kinds
        assert "remote_theme" in kinds
        assert "eval_exec" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_zola_scores_well(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(HARDENED_ZOLA, encoding="utf-8")
        analyzer = ZolaAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "zola.toml").write_text(HARDENED_ZOLA, encoding="utf-8")
        analyzer = ZolaAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(INSECURE_ZOLA, encoding="utf-8")
        analyzer = ZolaAnalyzer(str(tmp_path))
        assert "Zola configs:" in analyzer.summary()
        assert "Zola analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = ZolaAnalyzer(".").generate_hardened_template()
        assert "base_url" in template
        assert "127.0.0.1" in template

    def test_finding_format(self):
        finding = ZolaFinding(
            kind="insecure_http",
            severity="medium",
            message="test",
            path="config.toml",
            lineno=1,
        )
        assert "config.toml:1" in finding.format()
