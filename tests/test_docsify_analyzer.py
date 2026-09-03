"""Tests for DocsifyAnalyzer."""

from pathlib import Path

from devai.docsify_analyzer import DocsifyAnalyzer, DocsifyFinding


INSECURE_DOCSIFY = """\
<!DOCTYPE html>
<html>
<head><title>Docs</title></head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'Demo Docs',
      api_key: 'sk-live-hardcoded-secret',
      repo: 'https://user:pass@github.com/org/repo',
      requestHeaders: {
        Authorization: 'Bearer super-secret-token',
      },
      alias: {
        '/changelog': 'https://raw.example.com/CHANGELOG.md',
      },
      executeScript: true,
      mergeHeaders: true,
      externalLinkTarget: '_blank',
      plugins: [
        'https://cdn.example.com/docsify-plugin-foo.js',
      ],
    }
  </script>
  <script src="http://cdn.example.com/docsify.min.js"></script>
  <script src="//cdn.jsdelivr.net/npm/docsify/lib/docsify.min.js"></script>
</body>
</html>
"""

HARDENED_DOCSIFY = """\
<!DOCTYPE html>
<html>
<head><title>Docs</title></head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'Demo Docs',
      repo: 'https://github.com/org/repo',
      externalLinkTarget: '_blank',
      externalLinkRel: 'noopener noreferrer',
      executeScript: false,
      mergeHeaders: false,
    }
  </script>
  <script
    src="https://cdn.jsdelivr.net/npm/docsify@4/lib/docsify.min.js"
    integrity="sha384-example"
    crossorigin="anonymous"
  ></script>
</body>
</html>
"""


class TestDocsifyAnalyzer:
    def test_detects_insecure_docsify_config(self, tmp_path: Path):
        (tmp_path / "index.html").write_text(INSECURE_DOCSIFY, encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "credential_in_url" in kinds
        assert "request_headers_auth" in kinds
        assert "execute_script" in kinds
        assert "merge_headers" in kinds
        assert "remote_alias" in kinds
        assert "remote_plugin" in kinds
        assert "insecure_http" in kinds
        assert "protocol_relative_cdn" in kinds
        assert "external_link_blank" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_docsify_scores_well(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "index.html").write_text(HARDENED_DOCSIFY, encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "docsify.config.js").write_text(
            "window.$docsify = { name: 'Demo' }\n",
            encoding="utf-8",
        )
        analyzer = DocsifyAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "index.html").write_text(INSECURE_DOCSIFY, encoding="utf-8")
        analyzer = DocsifyAnalyzer(str(tmp_path))
        assert "Docsify configs:" in analyzer.summary()
        assert "Docsify analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = DocsifyAnalyzer(".").generate_hardened_template()
        assert "executeScript: false" in template
        assert "externalLinkRel" in template
        assert "integrity=" in template

    def test_finding_format(self):
        finding = DocsifyFinding(
            kind="test",
            severity="high",
            message="test message",
            path="index.html",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = DocsifyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
