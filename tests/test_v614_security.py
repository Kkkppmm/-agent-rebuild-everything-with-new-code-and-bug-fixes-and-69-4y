"""Tests for v6.14.0 security analyzers."""

from pathlib import Path

from devai import ProxyTrustAnalyzer, SecurityScanner


class TestProxyTrustAnalyzer:
    def test_clean_code_no_proxy_headers(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def get_client_ip(request):\n"
            "    return request.remote_addr\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_x_forwarded_for_get(self, tmp_path: Path):
        (tmp_path / "middleware.py").write_text(
            "def client_ip(request):\n"
            "    return request.headers.get('X-Forwarded-For')\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "proxy_header_access" for f in findings)

    def test_detects_django_meta_proxy_header(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def admin_check(request):\n"
            "    ip = request.META.get('HTTP_X_FORWARDED_FOR')\n"
            "    return ip in ALLOWED_IPS\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "proxy_header_access" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_proxy_header_in_access_control(self, tmp_path: Path):
        (tmp_path / "auth.py").write_text(
            "def is_allowed(request):\n"
            "    ip = request.headers.get('X-Real-IP')\n"
            "    if ip == '127.0.0.1':\n"
            "        return True\n"
            "    return False\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "proxy_header_auth" for f in findings)

    def test_detects_split_on_forwarded_for(self, tmp_path: Path):
        (tmp_path / "utils.py").write_text(
            "def client_ip(request):\n"
            "    forwarded = request.headers.get('X-Forwarded-For')\n"
            "    return forwarded.split(',')[0].strip()\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "proxy_header_client_ip" for f in findings)

    def test_allows_remote_addr(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def client_ip(request):\n"
            "    return request.environ.get('REMOTE_ADDR')\n",
            encoding="utf-8",
        )
        findings = ProxyTrustAnalyzer(str(tmp_path)).analyze()
        assert not findings


class TestProxyTrustScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "def ip(request):\n"
            "    return request.headers.get('X-Forwarded-For')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("proxy_trust",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "proxy_trust" for cat in report.categories)
