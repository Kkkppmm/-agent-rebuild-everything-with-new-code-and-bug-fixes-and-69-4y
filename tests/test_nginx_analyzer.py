"""Tests for NginxAnalyzer."""

from pathlib import Path

from devai.nginx_analyzer import NginxAnalyzer, NginxFinding

INSECURE_NGINX = """
server {
    listen 443;
    server_tokens on;
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:RC4:MD5;

    location / {
        autoindex on;
        proxy_pass http://backend:8000;
        add_header Access-Control-Allow-Origin *;
    }

    location /status {
        stub_status;
    }
}

server {
    listen 443 ssl;
    server_name api.example.com;
    # missing ssl_certificate and security headers
}
"""

HARDENED_NGINX = """
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.crt;
    ssl_certificate_key /etc/ssl/private/example.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    location ~ /\\. {
        deny all;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
"""


class TestNginxAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        conf_dir = tmp_path / "nginx" / "conf.d"
        conf_dir.mkdir(parents=True)
        (conf_dir / "site.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "weak_ssl_protocol" in kinds
        assert "weak_cipher" in kinds
        assert "server_tokens_on" in kinds
        assert "autoindex_on" in kinds
        assert "insecure_proxy_pass" in kinds
        assert "wildcard_cors" in kinds
        assert "unrestricted_stub_status" in kinds
        assert "listen_443_no_ssl" in kinds
        assert "ssl_listen_no_cert" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text(HARDENED_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1

    def test_finding_format(self):
        finding = NginxFinding(
            kind="weak_ssl_protocol",
            severity="high",
            message="test",
            path="nginx.conf",
            lineno=5,
            server="server@1",
        )
        assert "server@1" in finding.format()
        assert "nginx.conf:5" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = NginxAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "ssl_protocols" in template
        assert "Strict-Transport-Security" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text(INSECURE_NGINX, encoding="utf-8")
        analyzer = NginxAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Nginx Configuration Audit" in context
        assert "weak" in context.lower() or "high" in context
