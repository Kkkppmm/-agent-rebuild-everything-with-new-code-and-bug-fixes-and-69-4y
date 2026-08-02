"""Tests for MassAssignmentAnalyzer."""

from pathlib import Path

from devai.mass_assignment import MassAssignmentAnalyzer


SAFE_CODE = '''
def create_user(name, email):
    return User.objects.create(name=name, email=email)
'''

RISKY_CODE = '''
from django.http import JsonResponse

def create(request):
    User.objects.create(**request.json)
    Profile.objects.update_or_create(defaults=request.POST)
    return JsonResponse({"ok": True})
'''


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_request_data_in_orm(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "orm_create_request_data" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert "Mass assignment" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
