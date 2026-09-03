"""Tests for DocsifyAnalyzer."""

from pathlib import Path

from devai.docsify_analyzer import DocsifyAnalyzer, DocsifyFinding


INSECURE_INDEX = """\
<!DOCTYPE html>
<html>
<head><title>Docs</title></head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'Insecure Docs',
      api_key: 'sk-live-secret-token-12345',
      homepage: 'http://evil.example.com/README.md',
      basePath: '../outside/',
      executeScript: true,
      mergeHeaders: false,
      notFoundPage: false,
      loadSidebar: 'http://evil.example.com/_sidebar.md',
      requestHeaders: {
        'Authorization': 'Bearer hardcoded-token'
      },
      plugins: [
        'https://evil.example.com/malicious-plugin.js'
      ]
    };
  </script>
  <script src="//unpkg.com/docsify/lib/docsify.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/docsify@4/lib/plugins/search.min.js"></script>
</body>
</html>
"""

HARDENED_INDEX = """\
<!DOCTYPE html>
<html>
<head><title>Docs</title></head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'Secure Docs',
      repo: 'https://github.com/org/repo',
      homepage: 'README.md',
      loadSidebar: true,
      executeScript: false,
      mergeHeaders: true,
      notFoundPage: true,
      requestHeaders: {},
      plugins: []
    };
  </script>
  <script src="/docsify/lib/docsify.min.js"></script>
</body>
</html>
"""


class TestDocsifyAnalyzer:
    def test_detects_insecure_index_html(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(INSECURE_INDEX, encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "execute_script" in kinds
        assert "auth_header" in kinds
        assert "remote_sidebar" in kinds
        assert "unsafe_base_path" in kinds
        assert "remote_homepage" in kinds
        assert "remote_plugin" in kinds
        assert "cdn_script" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_index_scores_well(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(HARDENED_INDEX, encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_root_index_also_scanned(self, tmp_path: Path):
        (tmp_path / "index.html").write_text(
            "<script>window.$docsify = { executeScript: true };</script>",
            encoding="utf-8",
        )
        analyzer = DocsifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "execute_script" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocsifyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_non_docsify_index(self, tmp_path: Path):
        (tmp_path / "index.html").write_text("<html><body>Hello</body></html>", encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = DocsifyAnalyzer(".").generate_hardened_template()
        assert "executeScript: false" in template
        assert "requestHeaders: {}" in template

    def test_finding_format(self):
        finding = DocsifyFinding(
            kind="execute_script",
            severity="high",
            message="test message",
            path="docs/index.html",
            lineno=2,
        )
        assert "high" in finding.format()
        assert "docs/index.html:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(
            "<script>window.$docsify = { executeScript: true };</script>",
            encoding="utf-8",
        )
        analyzer = DocsifyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Docsify analysis:" in context
        assert "executeScript" in context

    def test_summary(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(
            "<script>window.$docsify = { executeScript: true };</script>",
            encoding="utf-8",
        )
        analyzer = DocsifyAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Docsify configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(
            "<script>window.$docsify = { executeScript: true, basePath: '../outside/' };</script>",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        docsify = next(c for c in report.categories if c.name == "docsify")
        assert docsify.score < 100.0
        assert docsify.details.get("findings", 0) > 0
