"""Tests for v6.35.0 security analyzers."""

from pathlib import Path

from devai import InsecureChannelsSettingsAnalyzer, SecurityScanner


class TestInsecureChannelsSettingsAnalyzer:
    def test_clean_channels_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CHANNEL_LAYERS = {\n"
            "    'default': {\n"
            "        'BACKEND': 'channels_redis.core.RedisChannelLayer',\n"
            "        'CONFIG': {\n"
            "            'hosts': ['redis://:secret@localhost:6379/0'],\n"
            "            'symmetric_encryption_keys': ['a' * 32],\n"
            "        },\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureChannelsSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_in_memory_channel_layer(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "CHANNEL_LAYERS = {\n"
            "    'default': {\n"
            "        'BACKEND': 'channels.layers.InMemoryChannelLayer',\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureChannelsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "in_memory_channel_layer" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_unauthenticated_redis_channel_layer(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CHANNEL_LAYERS = {\n"
            "    'default': {\n"
            "        'BACKEND': 'channels_redis.core.RedisChannelLayer',\n"
            "        'CONFIG': {'hosts': ['redis://localhost:6379/0']},\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureChannelsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unauthenticated_redis_channel_layer" for f in findings)

    def test_detects_weak_encryption_key(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "CHANNEL_LAYERS = {\n"
            "    'default': {\n"
            "        'BACKEND': 'channels_redis.core.RedisChannelLayer',\n"
            "        'CONFIG': {\n"
            "            'hosts': ['redis://:pw@localhost:6379/0'],\n"
            "            'symmetric_encryption_keys': ['django-insecure'],\n"
            "        },\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureChannelsSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "weak_channel_encryption_key" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "CHANNEL_LAYERS = {'default': {'BACKEND': 'channels.layers.InMemoryChannelLayer'}}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_channels_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_channels_settings" for cat in report.categories)
