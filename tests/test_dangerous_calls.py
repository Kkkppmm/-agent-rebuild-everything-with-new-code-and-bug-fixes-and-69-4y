"""Tests for DangerousCallsAnalyzer."""

from pathlib import Path

from devai.dangerous_calls import DangerousCall, DangerousCallsAnalyzer

SAFE_CODE = '''
import subprocess
import yaml

def run(cmd):
  subprocess.run(["echo", cmd], check=True)

def load_config(path):
  with open(path) as f:
    return yaml.safe_load(f)

def append(items, extra=None):
  if extra is None:
    extra = []
  return items + extra
'''

RISKY_CODE = '''
import os
import pickle
import subprocess

def run_cmd(cmd):
  os.system(cmd)

def deserialize(data):
  return pickle.loads(data)

def add_item(items=[]):
  items.append(1)
  return items

def dynamic(code):
  return eval(code)

def shell_out(cmd):
  subprocess.run(cmd, shell=True)
'''


class TestDangerousCallsAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = DangerousCallsAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DangerousCallsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "code_injection" in kinds
        assert "shell_injection" in kinds
        assert "deserialization" in kinds
        assert "mutable_default" in kinds
        assert analyzer.health_score() < 100.0

    def test_by_kind(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DangerousCallsAnalyzer(str(tmp_path))
        injection = analyzer.by_kind("code_injection")
        assert any(f.name == "eval" for f in injection)

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DangerousCallsAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 3

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = DangerousCallsAnalyzer(str(tmp_path))
        assert "Dangerous calls:" in analyzer.summary()
        assert "Dangerous call analysis" in analyzer.to_context()

    def test_format(self):
        finding = DangerousCall(
            path="app.py",
            name="eval",
            lineno=12,
            kind="code_injection",
            severity="high",
            message="eval() executes arbitrary code",
        )
        assert "app.py:12" in finding.format()
        assert "code_injection" in finding.format()
