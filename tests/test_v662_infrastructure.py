"""Tests for v6.62.0 infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, SemaphoreCIAnalyzer


class TestV662InfrastructureAnalyzers:
    def test_facade_semaphore_ci(self, tmp_path: Path):
        sem_dir = tmp_path / ".semaphore"
        sem_dir.mkdir()
        (sem_dir / "semaphore.yml").write_text(
            "version: v1.0\n"
            "blocks:\n"
            "  - name: Tests\n"
            "    task:\n"
            "      jobs:\n"
            "        - name: Run tests\n"
            "          commands:\n"
            "            - checkout\n"
            "            - python -m pytest\n",
            encoding="utf-8",
        )
        analyzer = DevAI.mock().semaphore_ci(tmp_path)
        assert isinstance(analyzer, SemaphoreCIAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_semaphore_ci_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        sem_dir = tmp_path / ".semaphore"
        sem_dir.mkdir()
        (sem_dir / "semaphore.yml").write_text(
            "version: v1.0\n"
            "blocks:\n"
            "  - name: Tests\n"
            "    task:\n"
            "      jobs:\n"
            "        - name: Run tests\n"
            "          commands:\n"
            "            - checkout\n"
            "            - python -m pytest\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "semaphore_ci" in names
