"""Tests for DevAI diff utilities."""

import tempfile
from pathlib import Path

from devai.utils.diff import (
    PatchResult,
    apply_unified_diff,
    extract_diff_from_text,
    parse_changed_files,
    summarize_diff,
)

SAMPLE_DIFF = """diff --git a/src/app.py b/src/app.py
index abc..def 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
 def main():
-    print("old")
+    print("new")
+    return 0
diff --git a/README.md b/README.md
index 111..222 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # App
+Updated docs
"""


class TestDiffUtils:
    def test_parse_changed_files(self):
        files = parse_changed_files(SAMPLE_DIFF)
        assert files == ["src/app.py", "README.md"]

    def test_summarize_diff(self):
        summary = summarize_diff(SAMPLE_DIFF)
        assert summary["files"] == ["src/app.py", "README.md"]
        assert summary["additions"] == 3
        assert summary["deletions"] == 1
        assert summary["hunks"] == 2

    def test_empty_diff(self):
        summary = summarize_diff("")
        assert summary["files"] == []
        assert summary["additions"] == 0
        assert summary["deletions"] == 0

    def test_extract_diff_from_markdown(self):
        text = "Here is the fix:\n```diff\ndiff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n```"
        diff = extract_diff_from_text(text)
        assert diff.startswith("diff --git a/foo.py")

    def test_apply_unified_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "src" / "app.py"
            target.parent.mkdir(parents=True)
            target.write_text('def main():\n    print("old")\n', encoding="utf-8")
            diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 def main():
-    print("old")
+    print("new")
+    return 0
"""
            result = apply_unified_diff(diff, root=root)
            assert isinstance(result, PatchResult)
            assert result.applied is True
            assert result.files_changed == ["src/app.py"]
            updated = target.read_text(encoding="utf-8")
            assert 'print("new")' in updated
            assert "return 0" in updated

    def test_apply_unified_diff_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app.py"
            original = 'print("old")\n'
            target.write_text(original, encoding="utf-8")
            diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print("old")
+print("new")
"""
            result = apply_unified_diff(diff, root=root, dry_run=True)
            assert result.files_changed == ["app.py"]
            assert target.read_text(encoding="utf-8") == original
