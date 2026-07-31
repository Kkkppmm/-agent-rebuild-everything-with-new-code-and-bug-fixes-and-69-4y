"""Tests for ProjectHealth."""

from pathlib import Path

from devai.project_health import ProjectHealth, ProjectHealthReport


GOOD_MODULE = '''
"""Module docstring."""

def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

BAD_MODULE = '''
def process(data):
    x = 1
    if x:
        if data:
            for i in range(10):
                if i % 2 == 0:
                    pass
    return data
'''


class TestProjectHealth:
    def test_analyze_good_project(self, tmp_path: Path):
        src = tmp_path / "src" / "app"
        src.mkdir(parents=True)
        (src / "math.py").write_text(GOOD_MODULE, encoding="utf-8")

        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_math.py").write_text("def test_add(): pass", encoding="utf-8")

        (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")

        health = ProjectHealth(str(tmp_path))
        report = health.analyze()
        assert isinstance(report, ProjectHealthReport)
        assert report.overall_score >= 60.0
        assert len(report.categories) == 10

    def test_analyze_detects_issues(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(BAD_MODULE, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        assert report.overall_score < 90.0
        assert any(c.name == "typing" and c.score < 100 for c in report.categories)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): pass\n", encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        assert "Project health" in health.summary()
        assert "Project health analysis" in health.to_context()

    def test_to_dict_json_markdown(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(GOOD_MODULE, encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        data = report.to_dict()
        assert "overall_score" in data
        assert "categories" in data
        assert report.to_json().startswith("{")
        md = report.to_markdown()
        assert "# Project Health Report" in md
        assert "Overall score" in md

    def test_recommendations_for_low_scores(self, tmp_path: Path):
        (tmp_path / "untyped.py").write_text("def bar(x): return x\n", encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        if any(c.name == "typing" and c.score < 80 for c in report.categories):
            assert any("type hint" in r.lower() for r in report.recommendations)

    def test_skip_secrets_scan(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        assert len(report.categories) == 9
        assert not any(c.name == "secrets" for c in report.categories)
        assert any(c.name == "smells" for c in report.categories)
        assert any(c.name == "tech_debt" for c in report.categories)
        assert any(c.name == "api_surface" for c in report.categories)
        assert any(c.name == "hotspots" for c in report.categories)
