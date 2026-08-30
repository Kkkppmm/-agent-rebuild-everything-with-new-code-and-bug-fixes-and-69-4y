"""Tests for v6.26.0 security analyzers."""

from pathlib import Path

from devai import InsecureCacheSettingsAnalyzer, SecurityScanner


class TestInsecureCacheSettingsAnalyzer:
    def test_clean_cache_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CACHES = {\n"
            "    'default': {\n"
            "        'BACKEND': 'django.core.cache.backends.redis.RedisCache',\n"
            "        'LOCATION': 'redis://:secret@redis:6379/1',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureCacheSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_locmem_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CACHES = {\n"
            "    'default': {\n"
            "        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureCacheSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "locmem_cache_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_redis_without_password(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CACHES = {\n"
            "    'default': {\n"
            "        'BACKEND': 'django.core.cache.backends.redis.RedisCache',\n"
            "        'LOCATION': 'redis://127.0.0.1:6379/1',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureCacheSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "redis_cache_no_password" for f in findings)

    def test_detects_dummy_cache_in_production(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "CACHES = {'default': {'BACKEND': 'django.core.cache.backends.dummy.DummyCache'}}\n",
            encoding="utf-8",
        )
        findings = InsecureCacheSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dummy_cache_in_production" for f in findings)

    def test_locmem_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_cache.py").write_text(
            "BACKEND = 'django.core.cache.backends.locmem.LocMemCache'\n",
            encoding="utf-8",
        )
        findings = InsecureCacheSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "locmem_cache_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_cache_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_cache_settings" for cat in report.categories)
