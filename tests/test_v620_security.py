"""Tests for v6.20.0 security analyzers."""

from pathlib import Path

from devai import InsecureDotenvAnalyzer, SecurityScanner


class TestInsecureDotenvAnalyzer:
    def test_clean_load_dotenv_default(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from dotenv import load_dotenv\nload_dotenv()\n",
            encoding="utf-8",
        )
        findings = InsecureDotenvAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_clean_load_dotenv_override_false(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from dotenv import load_dotenv\nload_dotenv(override=False)\n",
            encoding="utf-8",
        )
        findings = InsecureDotenvAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_override_true(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from dotenv import load_dotenv\nload_dotenv(override=True)\n",
            encoding="utf-8",
        )
        findings = InsecureDotenvAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dotenv_override_true" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_dotenv_module_call(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "import dotenv\ndotenv.load_dotenv(override=True)\n",
            encoding="utf-8",
        )
        findings = InsecureDotenvAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dotenv_override_true" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from dotenv import load_dotenv\nload_dotenv(override=True)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_dotenv",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_dotenv" for cat in report.categories)
