"""Tests for Pep723Analyzer."""

from pathlib import Path

from devai.pep723_analyzer import Pep723Analyzer, Pep723Finding

HARDENED_SCRIPT = '''\
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests==2.31.0",
#   "rich==13.7.0",
# ]
# ///

import requests

if __name__ == "__main__":
    print(requests.get("https://example.com").status_code)
'''

INSECURE_SCRIPT = '''\
# /// script
# dependencies = [
#   "requests>=2.0",
#   "flask",
#   "git+https://user:secret-token@github.com/example/bad-lib.git@main#egg=bad-lib",
#   "http://insecure-pypi.example.com/pkg.tar.gz",
# ]
# ///

import requests
import flask

if __name__ == "__main__":
    print("run")
'''

INVALID_TOML_SCRIPT = '''\
# /// script
# dependencies = [
#   "requests==2.31.0"
#   "flask==3.0.0",
# ]
# ///

import requests
'''

MISSING_METADATA_SCRIPT = '''\
import requests

if __name__ == "__main__":
    print(requests.get("https://example.com").status_code)
'''


class TestPep723Analyzer:
    def test_no_scripts_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_hardened_block_no_findings(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "deploy.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        assert analyzer.stats.blocks == 1
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_dependency" in kinds
        assert "loose_version" in kinds
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds
        assert "missing_requires_python" in kinds

    def test_detects_invalid_toml(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "broken.py").write_text(INVALID_TOML_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "invalid_toml" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_missing_metadata(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "fetch.py").write_text(MISSING_METADATA_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "missing_metadata" for f in findings)

    def test_finding_format(self):
        finding = Pep723Finding(
            kind="unpinned_dependency",
            severity="low",
            message="unpinned dependency",
            path="scripts/run.py",
            lineno=5,
            line="flask",
        )
        assert "scripts/run.py:5" in finding.format()

    def test_generate_template(self):
        template = Pep723Analyzer(".").generate_template()
        assert "# /// script" in template
        assert "requires-python" in template
        assert "dependencies" in template

    def test_to_context(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "run.py").write_text(INSECURE_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "PEP 723" in context
        assert "health score" in context

    def test_summary(self, tmp_path: Path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "run.py").write_text(HARDENED_SCRIPT, encoding="utf-8")
        analyzer = Pep723Analyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "PEP 723" in summary
        assert "block" in summary
