"""Tests for Pep723Analyzer."""

from pathlib import Path

from devai.pep723_analyzer import Pep723Analyzer, Pep723Finding


INSECURE_SCRIPT = '''\
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "requests",
#   "flask>=2.0",
#   "bad-lib @ git+https://user:secret@github.com/example/bad-lib.git@main",
#   "http://insecure.example.com/pkg.tar.gz",
# ]
# ///

print("hello")
'''

HARDENED_SCRIPT = '''\
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "httpx==0.27.0",
#   "rich==13.7.0",
# ]
# ///

print("hello")
'''

DUPLICATE_BLOCKS = '''\
# /// script
# dependencies = ["requests==2.31.0"]
# ///

# /// script
# dependencies = ["flask==3.0.0"]
# ///
'''

UNCLOSED_BLOCK = '''\
# /// script
# dependencies = ["requests==2.31.0"]

print("missing end marker")
'''


class TestPep723Analyzer:
    def test_no_scripts_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert analyzer.stats.scripts == 0
        assert analyzer.health_score() == 100.0

    def test_detects_script_file(self, tmp_path: Path):
        (tmp_path / "deploy.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert analyzer.stats.scripts == 1
        assert analyzer.stats.blocks == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_dependency" in kinds
        assert "loose_version" in kinds
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 80.0

    def test_hardened_script_scores_well(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_duplicate_script_blocks(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(DUPLICATE_BLOCKS, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "duplicate_script_block" in kinds

    def test_unclosed_block(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(UNCLOSED_BLOCK, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "unclosed_block" in kinds

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, Pep723Finding)
        assert "[" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert "PEP 723 scripts: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "PEP 723 analysis:" in context
        assert "requires-python=" in context

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = Pep723Analyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "# /// script" in template
        assert "requires-python" in template
