"""Tests for v6.72.0 infrastructure analyzers."""

from pathlib import Path

from devai import BuddyCIAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
- pipeline: "Hardened Pipeline"
  on: "PUSH"
  refs:
    - "refs/heads/main"
  actions:
    - action: "Test"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "3.12-slim"
      execute_commands:
        - "python -m pytest"
"""


class TestV672InfrastructureAnalyzers:
    def test_facade_buddy_ci(self, tmp_path: Path):
        buddy_dir = tmp_path / ".buddy"
        buddy_dir.mkdir()
        (buddy_dir / "pipeline.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().buddy_ci(tmp_path)
        assert isinstance(analyzer, BuddyCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_buddy_ci_category(self, tmp_path: Path):
        buddy_dir = tmp_path / ".buddy"
        buddy_dir.mkdir()
        (buddy_dir / "pipeline.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "buddy_ci" in names
