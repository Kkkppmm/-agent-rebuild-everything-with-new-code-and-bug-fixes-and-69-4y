"""Tests for v6.30.0 security analyzers."""

from pathlib import Path

from devai import InsecureStorageSettingsAnalyzer, SecurityScanner


class TestInsecureStorageSettingsAnalyzer:
    def test_clean_storage_settings(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'\n"
            "AWS_DEFAULT_ACL = 'private'\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_filesystem_storage(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "filesystem_storage_in_production" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_public_s3_acl(self, tmp_path: Path):
        (tmp_path / "production.py").write_text(
            "AWS_DEFAULT_ACL = 'public-read'\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "public_s3_acl" for f in findings)

    def test_detects_hardcoded_aws_credentials(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "hardcoded_aws_access_key" for f in findings)
        assert any(f.pattern == "hardcoded_aws_secret_key" for f in findings)

    def test_detects_storages_dict_backend(self, tmp_path: Path):
        (tmp_path / "prod.py").write_text(
            "STORAGES = {\n"
            "    'default': {\n"
            "        'BACKEND': 'django.core.files.storage.FileSystemStorage',\n"
            "    },\n"
            "}\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "filesystem_storage_in_production" for f in findings)

    def test_filesystem_ok_in_test_file(self, tmp_path: Path):
        (tmp_path / "test_storage.py").write_text(
            "DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'\n",
            encoding="utf-8",
        )
        findings = InsecureStorageSettingsAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "filesystem_storage_in_production" for f in findings)

    def test_integrated_security_scan(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text(
            "AWS_DEFAULT_ACL = 'public-read'\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("insecure_storage_settings",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "insecure_storage_settings" for cat in report.categories)
