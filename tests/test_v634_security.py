"""Tests for v6.34.0 security analyzers."""

from pathlib import Path

from devai import InsecureCelerySettingsAnalyzer, SecurityScanner


class TestInsecureCelerySettingsAnalyzer:
    def test_clean_celery_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CELERY_BROKER_URL = 'redis://:secret@localhost:6379/0'\n"
            "CELERY_RESULT_BACKEND = 'redis://:secret@localhost:6379/1'\n"
            "CELERY_TASK_ALWAYS_EAGER = False\n"
            "CELERY_TASK_SERIALIZER = 'json'\n"
            "CELERY_RESULT_SERIALIZER = 'json'\n"
            "CELERY_ACCEPT_CONTENT = ['json']\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_task_always_eager(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "task_always_eager = True\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "task_always_eager_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_pickle_task_serializer(self, tmp_path: Path):
        (tmp_path / "celery.py").write_text(
            "task_serializer = 'pickle'\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "pickle_task_serializer" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detects_pickle_accept_content(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "accept_content = ['json', 'pickle']\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "pickle_accept_content" for f in findings)

    def test_detects_redis_broker_without_password(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CELERY_BROKER_URL = 'redis://localhost:6379/0'\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "redis_broker_no_password" for f in findings)

    def test_detects_default_amqp_credentials(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "broker_url = 'amqp://guest:guest@localhost//'\n",
            encoding="utf-8",
        )
        findings = InsecureCelerySettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "default_amqp_credentials" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CELERY_TASK_SERIALIZER = 'pickle'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_celery_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_celery_settings" for cat in report.categories)
