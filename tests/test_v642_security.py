"""Tests for v6.42.0 security analyzers."""

from pathlib import Path

from devai import InsecureJwtSettingsAnalyzer, SecurityScanner


class TestInsecureJwtSettingsAnalyzer:
    def test_clean_jwt_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_ALGORITHM = 'RS256'\n"
            "ROTATE_REFRESH_TOKENS = True\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_hardcoded_jwt_secret(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SECRET = 'super_secret_jwt_key_12345'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_jwt_secret" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_none_algorithm(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "JWT_ALGORITHM = 'none'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "none_jwt_algorithm" for f in findings)

    def test_detects_skip_verification(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "payload = jwt.decode(token, key, algorithms=['HS256'], verify=False)\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "skip_jwt_verification" for f in findings)

    def test_detects_long_expiry(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ACCESS_TOKEN_LIFETIME = timedelta(days=365)\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "long_jwt_expiry" for f in findings)

    def test_detects_disabled_token_rotation(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "ROTATE_REFRESH_TOKENS = False\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "disabled_token_rotation" for f in findings)

    def test_detects_jwt_in_query_string(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "token = request.GET.get('token')\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "jwt_in_query_string" for f in findings)

    def test_detects_weak_signing_key(self, tmp_path: Path):
        (tmp_path / "jwt.py").write_text(
            "SIGNING_KEY = 'shortkey'\n",
            encoding="utf-8",
        )
        findings = InsecureJwtSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_signing_key" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "JWT_SIGNING_KEY = 'hardcoded_jwt_secret_value'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_jwt_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_jwt_settings" for cat in report.categories)
