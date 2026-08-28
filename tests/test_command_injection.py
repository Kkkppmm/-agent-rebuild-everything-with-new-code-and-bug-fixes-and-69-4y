"""Tests for CommandInjectionAnalyzer."""

from pathlib import Path

from devai.command_injection import CommandInjectionAnalyzer


SAFE_CODE = '''
import subprocess

def run_backup():
    subprocess.run(["tar", "-czf", "backup.tar.gz", "/data"], check=True)
'''

RISKY_CODE = '''
import os
import subprocess

def bad_system(user_cmd):
    os.system(f"ls {user_cmd}")

def bad_subprocess(user_input):
    subprocess.run(f"grep {user_input} /var/log/app.log", shell=True)

def bad_concat(cmd):
    os.popen("echo " + cmd)
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
        assert "dynamic_os_shell" in patterns
        assert "dynamic_subprocess_shell" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert "Command injection" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()

    def test_high_severity(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = CommandInjectionAnalyzer(str(tmp_path))
        assert len(analyzer.high_severity()) >= 2
