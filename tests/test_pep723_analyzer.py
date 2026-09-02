"""Tests for Pep723Analyzer."""

from pathlib import Path

from devai.pep723_analyzer import Pep723Analyzer, Pep723Finding


INSECURE_SCRIPT = '''\
#!/usr/bin/env python3
# /// script
# requires-python = ">=3"
# dependencies = [
#   "requests",
#   "evil==*",
#   "git+http://github.com/org/pkg.git",
# ]
# api_key = "hardcoded-secret-token-12345"
# ///

print("hello")
'''

HARDENED_SCRIPT = '''\
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "httpx==0.28.1",
#   "pydantic==2.10.6",
# ]
# ///

print("hello")
'''


class TestPep723Analyzer:
    def test_detects_insecure_script_block(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_dependency" in kinds
        assert "wildcard_version" in kinds
        assert "insecure_git_deps" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_script_clean(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.script_blocks == 1

    def test_no_blocks_returns_clean(self, tmp_path: Path):
        (tmp_path / "plain.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.summary().startswith("PEP 723 blocks: none found")

    def test_finding_format(self):
        finding = Pep723Finding(
            kind="unpinned_dependency",
            severity="medium",
            message="test message",
            path="run.py",
            lineno=5,
        )
        assert "[medium]" in finding.format()
        assert "run.py:5" in finding.format()

    def test_generate_template(self):
        template = Pep723Analyzer(".").generate_hardened_template()
        assert "/// script" in template
        assert "httpx==" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "run.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "PEP 723 inline script analysis" in context
        assert "health score" in context
