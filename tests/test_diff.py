"""Tests for DevAI diff utilities."""

from devai.utils.diff import parse_changed_files, summarize_diff

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
