"""Tests for MassAssignmentAnalyzer."""

from pathlib import Path

from devai.mass_assignment import MassAssignmentAnalyzer


SAFE_CODE = '''
def create_user(name, email):
    return User.create(name=name, email=email)
'''

RISKY_CODE = '''
def create_user(request):
    return User.objects.create(**request.data)

def update_user(request, user):
    user.update(request.form)
'''


class TestMassAssignmentAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_mass_assignment(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "orm_request_data" in patterns or "orm_request_kwargs" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = MassAssignmentAnalyzer(str(tmp_path))
        assert "Mass assignment" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
