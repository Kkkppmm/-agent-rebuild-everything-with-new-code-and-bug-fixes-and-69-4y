"""Tests for v6.25.0 security analyzers."""

from pathlib import Path

from devai import InsecureDatabaseSettingsAnalyzer, SecurityScanner


class TestInsecureDatabaseSettingsAnalyzer:
    def test_clean_database_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DATABASES = {\n"
            "    'default': {\n"
            "        'ENGINE': 'django.db.backends.postgresql',\n"
            "        'NAME': 'mydb',\n"
            "        'USER': os.environ['DB_USER'],\n"
            "        'PASSWORD': os.environ['DB_PASSWORD'],\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureDatabaseSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_sqlite_in_production(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DATABASES = {\n"
            "    'default': {\n"
            "        'ENGINE': 'django.db.backends.sqlite3',\n"
            "        'NAME': BASE_DIR / 'db.sqlite3',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureDatabaseSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "sqlite_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_empty_password(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DATABASES = {\n"
            "    'default': {\n"
            "        'ENGINE': 'django.db.backends.postgresql',\n"
            "        'USER': 'appuser',\n"
            "        'PASSWORD': '',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureDatabaseSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "empty_database_password" for f in findings)

    def test_detects_default_credentials(self, tmp_path: Path):
        (tmp_path / "config.py").write_text(
            "DATABASES = {\n"
            "    'default': {\n"
            "        'ENGINE': 'django.db.backends.postgresql',\n"
            "        'USER': 'postgres',\n"
            "        'PASSWORD': 'postgres',\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureDatabaseSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "default_database_credentials" for f in findings)

    def test_sqlite_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_models.py").write_text(
            "ENGINE = 'django.db.backends.sqlite3'\n",
            encoding="utf-8",
        )
        findings = InsecureDatabaseSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "sqlite_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3'}}\n",
            encoding="utf-8",
        )
        report = SecurityScanner(
            str(tmp_path), checks=("insecure_database_settings",)
        ).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_database_settings" for cat in report.categories)
