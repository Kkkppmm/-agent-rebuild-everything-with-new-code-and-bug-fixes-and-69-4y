"""Tests for MassAssignmentAnalyzer."""

from pathlib import Path

from devai.mass_assignment import MassAssignmentAnalyzer

SAFE_CODE = '''
def create_user(request):
    User.objects.create(username=request.json["username"], email=request.json["email"])
'''

RISKY_CODE = '''
def create_user(request):
    User.objects.create(**request.json)
'''


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []

    def test_detects_request_unpack(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert "Mass assignment" in analyzer.summary()
        assert "Mass assignment analysis:" in analyzer.to_context()
