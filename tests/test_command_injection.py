"""Tests for CommandInjectionAnalyzer."""

from pathlib import Path

from devai.command_injection import CommandInjectionAnalyzer

SAFE_CODE = '''
import subprocess

def run_git(args):
    return subprocess.run(["git", "status"], capture_output=True)
'''

RISKY_CODE = '''
import os
import subprocess

def run_user_cmd(user_input):
    os.system(user_input)

def shell_run(cmd):
    subprocess.run(cmd, shell=True)

def dynamic(user_cmd):
    subprocess.run(f"echo {user_cmd}", shell=True)
'''


class TestCommandInjectionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "subprocess_shell_true" in patterns or "os_shell_dynamic" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert "Command injection" in analyzer.summary()
        assert "Command injection analysis:" in analyzer.to_context()
