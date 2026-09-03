"""Tests for PelicanAnalyzer."""

from pathlib import Path

from devai.pelican_analyzer import PelicanAnalyzer, PelicanFinding


INSECURE_PELICAN = """\
#!/usr/bin/env python
# -*- coding: utf-8 -*-

AUTHOR = "Demo"
SITENAME = "Demo Blog"
SITEURL = "http://insecure.example.com"
GITHUB_TOKEN = "ghp_hardcoded_secret_token"

import sys
sys.path.insert(0, "/tmp/evil")

RELATIVE_URLS = True
LOAD_CONTENT_CACHE = False
DELETE_OUTPUT_DIRECTORY = False
DEVSERVER_HOST = "0.0.0.0"

JINJA_ENVIRONMENT = {"autoescape": False}

PLUGINS = [
    "sitemap",
    "pelican-shell",
]

PLUGIN_PATHS = ["../plugins"]

EXTRA_HEAD_TAGS = [
    "https://cdn.example.com/jquery.min.js",
]

GOOGLE_ANALYTICS = "https://www.google-analytics.com/analytics.js"

eval("print('bad')")
"""

HARDENED_PELICAN = """\
#!/usr/bin/env python
# -*- coding: utf-8 -*-

AUTHOR = "Demo"
SITENAME = "Demo Blog"
SITEURL = "https://example.com"

PATH = "content"
TIMEZONE = "UTC"
DEFAULT_LANG = "en"

RELATIVE_URLS = False
LOAD_CONTENT_CACHE = True
DELETE_OUTPUT_DIRECTORY = True

JINJA_ENVIRONMENT = {"autoescape": True}

PLUGINS = [
    "sitemap",
    "feed_summary",
]

EXTRA_HEAD_TAGS = []
"""


class TestPelicanAnalyzer:
    def test_detects_insecure_pelican_config(self, tmp_path: Path):
        (tmp_path / "pelicanconf.py").write_text(INSECURE_PELICAN, encoding="utf-8")
        analyzer = PelicanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "github_token" in kinds
        assert "unsafe_sys_path" in kinds
        assert "autoescape_disabled" in kinds
        assert "dangerous_plugin" in kinds
        assert "bind_all_interfaces" in kinds
        assert "eval_exec" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pelican_scores_well(self, tmp_path: Path):
        (tmp_path / "pelicanconf.py").write_text(HARDENED_PELICAN, encoding="utf-8")
        analyzer = PelicanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "publishconf.py").write_text(HARDENED_PELICAN, encoding="utf-8")
        analyzer = PelicanAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pelicanconf.py").write_text(INSECURE_PELICAN, encoding="utf-8")
        analyzer = PelicanAnalyzer(str(tmp_path))
        assert "Pelican configs:" in analyzer.summary()
        assert "Pelican analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = PelicanAnalyzer(".").generate_hardened_template()
        assert "SITEURL" in template
        assert "autoescape" in template

    def test_finding_format(self):
        finding = PelicanFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="pelicanconf.py",
            lineno=3,
        )
        assert "[medium]" in finding.format()

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = PelicanAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Pelican configs: none found"
