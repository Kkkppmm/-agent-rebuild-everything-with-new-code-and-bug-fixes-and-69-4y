"""Tests for MdBookAnalyzer."""

from pathlib import Path

from devai.mdbook_analyzer import MdBookAnalyzer, MdBookFinding


INSECURE_MDBOOK = """\
[book]
title = "Demo Docs"
authors = ["Demo"]
language = "en"
src = "src"
api_key = "sk-hardcoded-secret"

[build]
create-missing = true

[output.html]
site-url = "http://insecure.example.com/"
git-repository-url = "https://user:pass@github.com/org/repo"
edit-url-template = "https://github.com/org/repo/edit/main/{path}?token=ghp_hardcoded_secret"
additional-js = ["https://cdn.example.com/jquery.min.js"]
additional-css = ["https://cdn.example.com/style.css"]
google-analytics = "UA-123456-1"
cname = "http://docs.example.com"

[output.html.playground]
editable = true
copyable = true

eval("print('bad')")
"""

HARDENED_MDBOOK = """\
[book]
title = "Demo Docs"
authors = ["Demo"]
language = "en"
src = "src"

[build]
create-missing = false

[output.html]
site-url = "https://example.com/"
git-repository-url = "https://github.com/org/repo"
edit-url-template = "https://github.com/org/repo/edit/main/{path}"
additional-css = []
additional-js = []

[output.html.playground]
editable = false
copyable = true
"""


class TestMdBookAnalyzer:
    def test_detects_insecure_mdbook_config(self, tmp_path: Path):
        (tmp_path / "book.toml").write_text(INSECURE_MDBOOK, encoding="utf-8")
        analyzer = MdBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds
        assert "credential_in_url" in kinds
        assert "git_token" in kinds
        assert "remote_script" in kinds
        assert "editable_playground" in kinds
        assert "eval_exec" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_mdbook_scores_well(self, tmp_path: Path):
        (tmp_path / "book.toml").write_text(HARDENED_MDBOOK, encoding="utf-8")
        analyzer = MdBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "book.toml").write_text(HARDENED_MDBOOK, encoding="utf-8")
        analyzer = MdBookAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "book.toml").write_text(INSECURE_MDBOOK, encoding="utf-8")
        analyzer = MdBookAnalyzer(str(tmp_path))
        assert "mdBook configs:" in analyzer.summary()
        assert "mdBook analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = MdBookAnalyzer(".").generate_hardened_template()
        assert "site-url" in template
        assert "editable = false" in template

    def test_finding_format(self):
        finding = MdBookFinding(
            kind="insecure_http",
            severity="medium",
            message="test",
            path="book.toml",
            lineno=1,
        )
        assert "book.toml:1" in finding.format()
