"""Tests for UnsafeDeserializationAnalyzer."""

from pathlib import Path

from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer


class TestUnsafeDeserializationAnalyzer:
    def test_clean_project(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("import json\ndata = json.loads('{}')\n", encoding="utf-8")

        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_pickle_loads(self, tmp_path: Path):
        (tmp_path / "cache.py").write_text(
            "import pickle\nobj = pickle.loads(user_data)\n",
            encoding="utf-8",
        )
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any("pickle" in f.pattern for f in findings)

    def test_detects_unsafe_yaml_load(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "import yaml\ncfg = yaml.load(request_body)\n",
            encoding="utf-8",
        )
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.pattern == "yaml_load" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def foo(): return 1\n", encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert "Unsafe deserialization" in analyzer.summary()
        assert "Unsafe deserialization analysis:" in analyzer.to_context()
