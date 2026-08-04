"""Tests for SessionFixationAnalyzer."""

from pathlib import Path

from devai.session_fixation import SessionFixationAnalyzer


SAFE_CODE = '''
def authenticate(user):
    session.clear()
    session["uid"] = user.id
'''

RISKY_CODE = '''
def handle(request):
    token = request.args["session_id"]
    session["token"] = token
'''


class TestSessionFixationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "session_id_in_url" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = SessionFixationAnalyzer(str(tmp_path))
        assert "Session fixation" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
