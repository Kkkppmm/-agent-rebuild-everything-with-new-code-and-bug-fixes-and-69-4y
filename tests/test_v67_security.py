"""Tests for v6.7.0 security analyzers."""

from pathlib import Path

from devai import IDORAnalyzer, RaceConditionAnalyzer


class TestIDORAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def get_doc(user, doc_id):\n"
            "    doc = Document.get(doc_id)\n"
            "    if doc.owner_id != user.id:\n"
            "        raise PermissionError()\n"
            "    return doc\n",
            encoding="utf-8",
        )
        assert IDORAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_request_id_lookup(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "def get_document(request):\n"
            "    return Document.objects.get(id=request.args.get('id'))\n",
            encoding="utf-8",
        )
        findings = IDORAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unvalidated_id_lookup" for f in findings)

    def test_detects_filter_by_request_id(self, tmp_path: Path):
        (tmp_path / "api.py").write_text(
            "def fetch_user(request):\n"
            "    return User.query.filter_by(id=request.json['user_id']).first()\n",
            encoding="utf-8",
        )
        findings = IDORAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "unvalidated_id_lookup" for f in findings)


class TestRaceConditionAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "def save(path, data):\n    with open(path, 'w') as f:\n        f.write(data)\n",
            encoding="utf-8",
        )
        assert RaceConditionAnalyzer(str(tmp_path)).analyze() == []

    def test_detects_toctou_pattern(self, tmp_path: Path):
        (tmp_path / "file.py").write_text(
            "import os\n\n"
            "def write_if_missing(path, data):\n"
            "    if not os.path.exists(path):\n"
            "        open(path, 'w').write(data)\n",
            encoding="utf-8",
        )
        findings = RaceConditionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "toctou_check_then_write" for f in findings)

    def test_detects_global_mutation_with_threading(self, tmp_path: Path):
        (tmp_path / "worker.py").write_text(
            "import threading\n\ncounter = 0\n\n"
            "def increment():\n"
            "    global counter\n"
            "    counter += 1\n",
            encoding="utf-8",
        )
        findings = RaceConditionAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "global_mutation" for f in findings)
