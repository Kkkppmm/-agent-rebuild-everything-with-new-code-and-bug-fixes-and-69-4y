"""Tests for NamingConventionAnalyzer."""

from pathlib import Path

from devai.naming_conventions import NamingConventionAnalyzer, NamingViolation


GOOD_CODE = '''
MAX_RETRIES = 3

class UserService:
    def get_user(self, user_id: int):
        return user_id

def process_data(raw_input):
    return raw_input
'''

BAD_CODE = '''
class userService:
  def GetUser(self, UserID):
    BadVariable = 1
    return UserID

def ProcessData():
    pass
'''


class TestNamingConventionAnalyzer:
    def test_no_violations(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(GOOD_CODE, encoding="utf-8")
        analyzer = NamingConventionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_violations(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        analyzer = NamingConventionAnalyzer(str(tmp_path))
        violations = analyzer.analyze()
        kinds = {v.kind for v in violations}
        assert "class" in kinds
        assert "method" in kinds
        assert "function" in kinds
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        analyzer = NamingConventionAnalyzer(str(tmp_path))
        classes = analyzer.by_kind("class")
        assert len(classes) == 1
        assert classes[0].name == "userService"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(BAD_CODE, encoding="utf-8")
        analyzer = NamingConventionAnalyzer(str(tmp_path))
        assert "Naming:" in analyzer.summary()
        assert "Naming convention analysis" in analyzer.to_context()

    def test_format(self):
        violation = NamingViolation(
            path="app.py",
            name="GetUser",
            lineno=3,
            kind="method",
            expected="snake_case",
            message="'GetUser' should use lowercase_with_underscores",
        )
        assert "app.py:3" in violation.format()
        assert "snake_case" in violation.format()

    def test_allows_dunder_methods(self, tmp_path: Path):
        code = """
class Foo:
    def __init__(self):
        pass
    def __repr__(self):
        return 'Foo'
"""
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
        analyzer = NamingConventionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
