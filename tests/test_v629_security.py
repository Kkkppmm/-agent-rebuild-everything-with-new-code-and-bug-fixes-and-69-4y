"""Tests for v6.29.0 security analyzers."""

from pathlib import Path

from devai import InsecureCorsSettingsAnalyzer, SecurityScanner


class TestInsecureCorsSettingsAnalyzer:
    def test_clean_cors_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "CORS_ALLOW_CREDENTIALS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_allow_all_origins(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("CORS_ALLOW_ALL_ORIGINS = True\n", encoding="utf-8")
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_allow_all_origins" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_wildcard_origins(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "CORS_ALLOWED_ORIGINS = ['*']\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_wildcard_origin" for f in findings)

    def test_detects_credentials_with_permissive_origins(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOW_ALL_ORIGINS = True\n"
            "CORS_ALLOW_CREDENTIALS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_credentials_with_permissive_origins" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_legacy_origin_allow_all(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("CORS_ORIGIN_ALLOW_ALL = True\n", encoding="utf-8")
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_allow_all_origins" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("CORS_ALLOW_ALL_ORIGINS = True\n", encoding="utf-8")
        report = SecurityScanner(str(tmp_path), checks=("insecure_cors_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_cors_settings" for cat in report.categories)
