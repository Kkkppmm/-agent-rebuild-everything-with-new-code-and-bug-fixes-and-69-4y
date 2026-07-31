"""Tests for CommandInjectionAnalyzer."""

from pathlib import Path

from devai.command_injection import CommandInjectionAnalyzer

SAFE_CODE = '''
import subprocess

def run_git(args: list[str]):
    return subprocess.run(["git"] + args, check=True, capture_output=True)
'''

RISKY_CODE = '''
import os
import subprocess

def run_user_command(user_input: str):
    os.system(f"echo {user_input}")

def run_shell(cmd: str):
    subprocess.run(f"ls {cmd}", shell=True)
'''


class TestCommandInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_dynamic_commands(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert any(f.severity == "high" for f in findings)
        assert analyzer.health_score() < 100.0

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        high = analyzer.high_severity()
        assert all(f.severity == "high" for f in high)
        assert len(high) >= 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert "Command injection" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
