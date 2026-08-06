"""Tests for v6.29.0 security analyzers."""

from pathlib import Path

from devai import InsecureCorsSettingsAnalyzer, SecurityScanner


class TestInsecureCorsSettingsAnalyzer:
    def test_clean_cors_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "CORS_ALLOW_CREDENTIALS = False\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_allow_all_origins(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOW_ALL_ORIGINS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_allow_all_origins" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_wildcard_origin_list(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "CORS_ALLOWED_ORIGINS = ['*']\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_wildcard_origin" for f in findings)

    def test_detects_credentials_with_wildcard(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOW_ALL_ORIGINS = True\n"
            "CORS_ALLOW_CREDENTIALS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "cors_allow_credentials" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_credentials_without_wildcard_is_medium(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "CORS_ALLOW_CREDENTIALS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        cred = [f for f in findings if f.pattern == "cors_allow_credentials"]
        assert cred
        assert cred[0].severity == "medium"

    def test_wildcard_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_cors.py").write_text(
            "CORS_ALLOW_ALL_ORIGINS = True\n",
            encoding="utf-8",
        )
        findings = InsecureCorsSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CORS_ALLOW_ALL_ORIGINS = True\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_cors_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_cors_settings" for cat in report.categories)
