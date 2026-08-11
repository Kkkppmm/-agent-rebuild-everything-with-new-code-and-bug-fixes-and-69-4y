"""Tests for v6.10.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, ZipSlipAnalyzer


class TestZipSlipAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "safe.py").write_text(
            "import zipfile\n"
            "from pathlib import Path\n\n"
            "def safe_extract(archive: str, dest: str) -> None:\n"
            "    with zipfile.ZipFile(archive) as zf:\n"
            "        for member in zf.namelist():\n"
            "            if member.startswith('/') or '..' in Path(member).parts:\n"
            "                raise ValueError('unsafe path')\n"
            "            zf.extract(member, dest)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "unsafe_extractall" for f in findings)

    def test_detects_extractall(self, tmp_path: Path):
        (tmp_path / "unsafe.py").write_text(
            "import zipfile\n\n"
            "def unpack(path, dest):\n"
            "    with zipfile.ZipFile(path) as zf:\n"
            "        zf.extractall(dest)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unsafe_extractall" for f in findings)

    def test_detects_unpack_archive(self, tmp_path: Path):
        (tmp_path / "deploy.py").write_text(
            "import shutil\n\n"
            "def deploy(pkg, target):\n"
            "    shutil.unpack_archive(pkg, target)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unsafe_unpack_archive" for f in findings)

    def test_detects_dynamic_extract(self, tmp_path: Path):
        (tmp_path / "handler.py").write_text(
            "import zipfile\n\n"
            "def extract_member(zf, name, dest):\n"
            "    zf.extract(name, dest)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dynamic_extract" for f in findings)

    def test_detects_tarfile_without_filter(self, tmp_path: Path):
        (tmp_path / "backup.py").write_text(
            "import tarfile\n\n"
            "def restore(path, dest):\n"
            "    with tarfile.open(path) as tar:\n"
            "        tar.extractall(dest)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern in {"unsafe_extractall", "tarfile_no_filter"} for f in findings)

    def test_allows_literal_extract(self, tmp_path: Path):
        (tmp_path / "assets.py").write_text(
            "import zipfile\n\n"
            "def extract_readme(zf, dest):\n"
            "    zf.extract('README.md', dest)\n",
            encoding="utf-8",
        )
        findings = ZipSlipAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "dynamic_extract" for f in findings)


class TestZipSlipSecurityScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "import shutil\nshutil.unpack_archive('pkg.zip', '/tmp/out')\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("zip_slip",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "zip_slip" for cat in report.categories)
