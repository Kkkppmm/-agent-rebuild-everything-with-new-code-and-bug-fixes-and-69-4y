"""Tests for ExceptionHierarchyAnalyzer."""

from pathlib import Path

from devai.exception_analyzer import ExceptionHierarchyAnalyzer


CUSTOM_EXCEPTIONS = '''
class AppError(Exception):
    """Base app error."""

class ValidationError(AppError):
    """Validation failed."""

def run():
    try:
        raise ValidationError("bad")
    except Exception:
        pass
'''

BARE_EXCEPT = '''
def risky():
    try:
        x = 1
    except:
        pass
'''


class TestExceptionHierarchyAnalyzer:
    def test_detects_custom_exceptions(self, tmp_path: Path):
        (tmp_path / "errors.py").write_text(CUSTOM_EXCEPTIONS, encoding="utf-8")
        analyzer = ExceptionHierarchyAnalyzer(str(tmp_path))
        exceptions = analyzer.analyze()
        names = {e.name for e in exceptions}
        assert "AppError" in names
        assert "ValidationError" in names

    def test_detects_broad_handlers(self, tmp_path: Path):
        (tmp_path / "errors.py").write_text(CUSTOM_EXCEPTIONS, encoding="utf-8")
        analyzer = ExceptionHierarchyAnalyzer(str(tmp_path))
        handlers = analyzer.broad_handlers
        assert len(handlers) >= 1
        assert any(h.handler_type == "broad except" for h in handlers)

    def test_detects_bare_except(self, tmp_path: Path):
        (tmp_path / "risky.py").write_text(BARE_EXCEPT, encoding="utf-8")
        analyzer = ExceptionHierarchyAnalyzer(str(tmp_path))
        handlers = analyzer.broad_handlers
        assert any(h.handler_type == "bare except" for h in handlers)

    def test_health_score_penalizes_bare_except(self, tmp_path: Path):
        (tmp_path / "risky.py").write_text(BARE_EXCEPT, encoding="utf-8")
        analyzer = ExceptionHierarchyAnalyzer(str(tmp_path))
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "errors.py").write_text(CUSTOM_EXCEPTIONS, encoding="utf-8")
        analyzer = ExceptionHierarchyAnalyzer(str(tmp_path))
        assert "Custom exceptions" in analyzer.summary()
        assert "Exception analysis" in analyzer.to_context()
