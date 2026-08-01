"""Tests for UnsafeDeserializationAnalyzer."""

from pathlib import Path

from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer


SAFE_CODE = '''
import json
import yaml

def load_config(data):
    return json.loads(data)

def load_yaml(data):
    return yaml.safe_load(data)
'''

RISKY_CODE = '''
import pickle
import yaml
import marshal

def load_pickle(data):
    return pickle.loads(data)

def load_yaml_unsafe(data):
    return yaml.load(data)

def load_marshal(data):
    return marshal.loads(data)
'''


class TestUnsafeDeserializationAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "pickle_loads" in patterns
        assert "yaml_load_no_loader" in patterns
        assert "marshal_loads" in patterns
        assert len(analyzer.critical_findings()) >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = UnsafeDeserializationAnalyzer(str(tmp_path))
        assert "Unsafe deserialization" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
