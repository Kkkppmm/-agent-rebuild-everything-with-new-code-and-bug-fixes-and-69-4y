"""Tests for MassAssignmentAnalyzer."""

from pathlib import Path

from devai.mass_assignment import MassAssignmentAnalyzer


SAFE_CODE = '''
def create_user(data):
    User.objects.create(username=data["username"], email=data["email"])
'''

RISKY_CODE = '''
from flask import request

def bad_create():
    User.objects.create(**request.form)

def bad_update():
    User.objects.update(**request.json)

def bad_model():
    user = User(**request.get_json())
'''


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "create_kwargs_unpack" in patterns
        assert "update_kwargs_unpack" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert "Mass assignment" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
