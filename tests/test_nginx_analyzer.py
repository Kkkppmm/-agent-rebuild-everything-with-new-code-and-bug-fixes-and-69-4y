"""Tests for NginxAnalyzer."""

from pathlib import Path

from devai.nginx_analyzer import NginxAnalyzer, NginxFinding


INSECURE_NGINX = """
server {
    listen 443 ssl;
    server_tokens on;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    autoindex on;

    add_header Access-Control-Allow-Origin *;

    location / {
        proxy_pass http://backend:8080;
        proxy_ssl_verify off;
    }
}
"""

HARDENED_NGINX = """
server {
    listen 443 ssl http2;
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass https://backend:8443;
        proxy_ssl_verify on;
    }
}
"""


class TestNginxAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        nginx = tmp_path / "nginx"
        nginx.mkdir()
        (nginx / "site.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "weak_tls" in kinds
        assert "server_tokens_on" in kinds
        assert "autoindex_on" in kinds
        assert "wildcard_cors" in kinds
        assert "insecure_proxy_pass" in kinds
        assert "ssl_verify_off" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_nginx_scores_well(self, tmp_path: Path):
        nginx = tmp_path / "nginx"
        nginx.mkdir()
        (nginx / "site.conf").write_text(HARDENED_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text(HARDENED_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        assert "Nginx" in analyzer.summary()
        assert "Nginx analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "Strict-Transport-Security" in template

    def test_finding_format(self):
        finding = NginxFinding(
            kind="weak_tls",
            severity="high",
            message="weak TLS",
            path="nginx/site.conf",
            lineno=4,
        )
        assert "site.conf:4" in finding.format()
