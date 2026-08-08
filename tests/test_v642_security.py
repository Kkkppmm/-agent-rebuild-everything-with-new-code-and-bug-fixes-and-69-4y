"""Tests for v6.42.0 security analyzers."""

from pathlib import Path

from devai import (
    InsecureKafkaSettingsAnalyzer,
    InsecureMongoSettingsAnalyzer,
    InsecureRedisSettingsAnalyzer,
    SecurityScanner,
)


class TestInsecureRedisSettingsAnalyzer:
    def test_clean_redis_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REDIS_URL = os.environ['REDIS_URL']\n"
            "REDIS_SSL = True\n",
            encoding="utf-8",
        )
        findings = InsecureRedisSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_no_auth_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REDIS_URL = 'redis://localhost:6379/0'\n",
            encoding="utf-8",
        )
        findings = InsecureRedisSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "redis_no_auth" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_ssl_disabled(self, tmp_path: Path):
        (tmp_path / "redis.py").write_text(
            "REDIS_SSL = False\n",
            encoding="utf-8",
        )
        findings = InsecureRedisSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "redis_ssl_disabled" for f in findings)

    def test_detects_hardcoded_password(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "REDIS_PASSWORD = 'my-redis-secret'\n",
            encoding="utf-8",
        )
        findings = InsecureRedisSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_redis_password" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "REDIS_URL = 'redis://localhost:6379'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_redis_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_redis_settings" for cat in report.categories)


class TestInsecureMongoSettingsAnalyzer:
    def test_clean_mongo_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MONGO_URI = os.environ['MONGO_URI']\n"
            "MONGO_TLS = True\n",
            encoding="utf-8",
        )
        findings = InsecureMongoSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_no_auth_url(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MONGO_URI = 'mongodb://localhost:27017/mydb'\n",
            encoding="utf-8",
        )
        findings = InsecureMongoSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "mongo_no_auth" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_tls_disabled(self, tmp_path: Path):
        (tmp_path / "mongo.py").write_text(
            "MONGO_TLS = False\n",
            encoding="utf-8",
        )
        findings = InsecureMongoSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "mongo_tls_disabled" for f in findings)

    def test_detects_hardcoded_password(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "MONGO_PASSWORD = 'mongo-secret-123'\n",
            encoding="utf-8",
        )
        findings = InsecureMongoSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_mongo_password" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "MONGO_TLS = False\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_mongo_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_mongo_settings" for cat in report.categories)


class TestInsecureKafkaSettingsAnalyzer:
    def test_clean_kafka_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURITY_PROTOCOL = 'SASL_SSL'\n"
            "SASL_MECHANISM = 'SCRAM-SHA-256'\n",
            encoding="utf-8",
        )
        findings = InsecureKafkaSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_plaintext_protocol(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURITY_PROTOCOL = 'PLAINTEXT'\n",
            encoding="utf-8",
        )
        findings = InsecureKafkaSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "kafka_plaintext_protocol" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_weak_sasl(self, tmp_path: Path):
        (tmp_path / "kafka.py").write_text(
            "SASL_MECHANISM = 'PLAIN'\n",
            encoding="utf-8",
        )
        findings = InsecureKafkaSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "kafka_weak_sasl" for f in findings)

    def test_detects_ssl_disabled(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "KAFKA_SSL = False\n",
            encoding="utf-8",
        )
        findings = InsecureKafkaSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "kafka_ssl_disabled" for f in findings)

    def test_detects_hardcoded_password(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "KAFKA_PASSWORD = 'kafka-secret-key'\n",
            encoding="utf-8",
        )
        findings = InsecureKafkaSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_kafka_password" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "SECURITY_PROTOCOL = 'PLAINTEXT'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_kafka_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_kafka_settings" for cat in report.categories)
