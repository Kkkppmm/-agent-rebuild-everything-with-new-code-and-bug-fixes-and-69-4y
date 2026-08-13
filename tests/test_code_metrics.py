"""Tests for DevAI CodeMetrics."""

from pathlib import Path

from devai.code_metrics import CodeMetrics, FileMetrics, FunctionMetrics, ProjectMetrics


SIMPLE = """
def add(a: int, b: int) -> int:
    return a + b
"""

COMPLEX = """
def process(items):
    result = []
    for item in items:
        if item > 0:
            if item % 2 == 0:
                result.append(item)
            elif item % 3 == 0:
                result.append(item * 2)
        else:
            try:
                result.append(abs(item))
            except ValueError:
                pass
    return result
"""

CLASS_SAMPLE = """
class Service:
    def run(self, x: int) -> int:
        return x

    def complex(self, data):
        for row in data:
            if row and row.get("active"):
                yield row
"""


class TestCodeMetrics:
    def test_simple_function(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        metrics.analyze()
        assert metrics.project.total_functions == 1
        assert metrics.project.total_sloc >= 2
        assert metrics.functions[0].complexity == 1

    def test_complex_function(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(COMPLEX, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        metrics.analyze()
        fn = metrics.functions[0]
        assert fn.complexity >= 5
        assert fn.name == "process"

    def test_class_methods(self, tmp_path: Path):
        (tmp_path / "svc.py").write_text(CLASS_SAMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        metrics.analyze()
        assert metrics.project.total_classes == 1
        assert metrics.project.total_functions == 2
        names = {f.name for f in metrics.functions}
        assert "Service.run" in names
        assert "Service.complex" in names

    def test_top_complex(self, tmp_path: Path):
        (tmp_path / "simple.py").write_text(SIMPLE, encoding="utf-8")
        (tmp_path / "complex.py").write_text(COMPLEX, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        top = metrics.top_complex(1)
        assert top[0].name == "process"

    def test_high_complexity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(COMPLEX, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path), complexity_threshold=3)
        high = metrics.high_complexity()
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        summary = metrics.summary()
        assert "SLOC" in summary
        context = metrics.to_context()
        assert "Code metrics" in context

    def test_to_dict(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        data = metrics.to_dict()
        assert data["project"]["files"] == 1
        assert "top_complex" in data

    def test_file_metrics_format(self):
        fm = FileMetrics("app.py", 10, 8, 1, 1, 2, 1, 3, 2.0)
        assert "app.py" in fm.format()
        assert "8 sloc" in fm.format()

    def test_function_metrics_format(self):
        fn = FunctionMetrics("foo", "app.py", 1, 5, 2, 10, is_async=True)
        assert "async foo()" in fn.format()
        assert "complexity=5" in fn.format()

    def test_project_avg_sloc(self):
        p = ProjectMetrics(2, 20, 16, 4, 1, 3.0, 5, 0)
        assert p.avg_sloc_per_file == 8.0

    def test_empty_project(self, tmp_path: Path):
        metrics = CodeMetrics(str(tmp_path))
        metrics.analyze()
        assert metrics.project.files == 0
        assert metrics.project.avg_complexity == 0.0

    def test_ignores_pycache(self, tmp_path: Path):
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "mod.py").write_text(COMPLEX, encoding="utf-8")
        (tmp_path / "app.py").write_text(SIMPLE, encoding="utf-8")
        metrics = CodeMetrics(str(tmp_path))
        metrics.analyze()
        assert metrics.project.files == 1
