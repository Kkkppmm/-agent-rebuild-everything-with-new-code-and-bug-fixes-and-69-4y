"""Tests for v6.39.0 security analyzers."""

from pathlib import Path

from devai import InsecureCspSettingsAnalyzer, SecurityScanner


class TestInsecureCspSettingsAnalyzer:
    def test_clean_csp_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSP_DEFAULT_SRC = (\"'self'\",)\n"
            "CSP_SCRIPT_SRC = (\"'self'\", \"'nonce-{nonce}'\")\n"
            "CSP_STYLE_SRC = (\"'self'\", \"'nonce-{nonce}'\")\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_unsafe_inline(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSP_SCRIPT_SRC = (\"'self'\", \"'unsafe-inline'\")\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unsafe_inline" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_unsafe_eval(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "CSP_SCRIPT_SRC = (\"'self'\", \"'unsafe-eval'\")\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unsafe_eval" for f in findings)

    def test_detects_wildcard_source(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSP_DEFAULT_SRC = ('*',)\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "wildcard_source" for f in findings)

    def test_detects_disabled_csp(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSP_ENABLED = False\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "csp_disabled" for f in findings)

    def test_detects_report_only_mode(self, tmp_path: Path):
        (tmp_path / "middleware.py").write_text(
            "response['Content-Security-Policy-Report-Only'] = \"default-src 'self'\"\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "report_only_mode" for f in findings)

    def test_detects_flask_talisman_unsafe_inline(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "content_security_policy = {\"script-src\": [\"'self'\", \"'unsafe-inline'\"]}\n",
            encoding="utf-8",
        )
        findings = InsecureCspSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unsafe_inline" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CSP_SCRIPT_SRC = (\"'unsafe-inline'\",)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_csp_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_csp_settings" for cat in report.categories)
