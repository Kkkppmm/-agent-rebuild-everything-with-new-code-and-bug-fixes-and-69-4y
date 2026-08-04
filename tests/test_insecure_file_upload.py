"""Tests for InsecureFileUploadAnalyzer."""

from pathlib import Path

from devai.insecure_file_upload import InsecureFileUploadAnalyzer


SAFE_CODE = '''
from werkzeug.utils import secure_filename

def upload(file):
  name = secure_filename(file.filename)
  file.save(name)
'''

RISKY_CODE = '''
def upload(request):
    f = request.files["upload"]
    f.save(f.filename)
    open(f.filename, "wb").write(f.read())
'''


class TestInsecureFileUploadAnalyzer:
    def test_clean_code(self, tmp_path: Path):
        (tmp_path / "uploads.py").write_text(SAFE_CODE, encoding="utf-8")
        analyzer = InsecureFileUploadAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_detects_risky_patterns(self, tmp_path: Path):
        (tmp_path / "uploads.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureFileUploadAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        patterns = {f.pattern for f in findings}
        assert "unsanitized_save" in patterns
        assert "user_controlled_write" in patterns
        assert analyzer.health_score() < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "uploads.py").write_text(RISKY_CODE, encoding="utf-8")
        analyzer = InsecureFileUploadAnalyzer(str(tmp_path))
        assert "Insecure file upload" in analyzer.summary()
        assert "Findings:" in analyzer.to_context()
