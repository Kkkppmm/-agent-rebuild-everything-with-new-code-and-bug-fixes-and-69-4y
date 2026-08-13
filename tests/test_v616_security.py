"""Tests for v6.16.0 security analyzers."""

from pathlib import Path

from devai import CredentialsInURLAnalyzer, SecurityScanner


class TestCredentialsInURLAnalyzer:
    def test_clean_code_no_credentials(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'API_URL = "https://api.example.com/v1/data"\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_embedded_credentials(self, tmp_path: Path):
        (tmp_path / "db.py").write_text(
            'url = "postgresql://admin:secretpass@db.example.com/mydb"\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "url_embedded_credentials" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_query_string_secret(self, tmp_path: Path):
        (tmp_path / "client.py").write_text(
            'url = "https://api.example.com/data?api_key=sk_live_abc123xyz"\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "query_string_secret" for f in findings)

    def test_detects_hardcoded_bearer_token(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            'headers = {"Authorization": "Bearer sk_test_abcdefghijkl"}\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_bearer_token" for f in findings)

    def test_allows_env_var_patterns(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            'url = f"https://api.example.com?api_key={os.environ[\'API_KEY\']}"\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_allows_placeholder_credentials(self, tmp_path: Path):
        (tmp_path / "template.py").write_text(
            'url = "mongodb://{user}:{password}@localhost/test"\n',
            encoding="utf-8",
        )
        findings = CredentialsInURLAnalyzer(str(tmp_path)).analyze()
        assert not findings


class TestCredentialsInURLScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            'url = "redis://user:pass123@cache.example.com:6379"\n',
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("credentials_in_url",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "credentials_in_url" for cat in report.categories)
