"""Batch review multiple files with DevAI."""

from pathlib import Path

from devai import quickstart
from devai.batch_review import BatchReviewer

runtime = quickstart(use_mock=True)
reviewer = BatchReviewer(runtime.assistant)

# Review a directory of Python files
report = reviewer.review_directory(Path("src/devai"), pattern="*.py", recursive=True)
print(report.summary())
print()
print(report.to_markdown()[:500], "...")
