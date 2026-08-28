"""Tests for ViteAnalyzer."""

from pathlib import Path

from devai.vite_analyzer import ViteAnalyzer, ViteFinding


INSECURE_VITE_CONFIG = """\
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: true,
    https: false,
    cors: true,
    fs: { strict: false },
    allowedHosts: true,
  },
  build: {
    sourcemap: 'inline',
    minify: false,
  },
  define: {
    API_KEY: 'hardcoded_secret_value_12345',
  },
  proxy: {
    '/api': { target: 'http://internal.service/api' },
  },
});
"""

HARDENED_VITE_CONFIG = """\
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'localhost',
    https: true,
    cors: { origin: ['http://localhost:5173'], credentials: false },
    fs: { strict: true },
  },
  build: {
    sourcemap: false,
    minify: 'esbuild',
  },
});
"""


class TestViteAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"devDependencies": {"vite": "^5.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(INSECURE_VITE_CONFIG, encoding="utf-8")
        analyzer = ViteAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "fs_strict_false" in kinds
        assert "https_false" in kinds
        assert "sourcemap_inline" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"devDependencies": {"vite": "^5.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(HARDENED_VITE_CONFIG, encoding="utf-8")
        analyzer = ViteAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].has_server_block

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ViteAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = ViteFinding(
            kind="fs_strict_false",
            severity="high",
            message="test message",
            path="vite.config.ts",
            lineno=8,
            line="fs: { strict: false }",
        )
        assert "vite.config.ts:8" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = ViteAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "defineConfig" in template
        assert "fs: { strict: true }" in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "package.json").write_text(
            '{"devDependencies": {"vite": "^5.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "vite.config.ts").write_text(
            "export default { server: { fs: { strict: false } } };\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        vite = next(c for c in report.categories if c.name == "vite")
        assert vite.score < 100.0
        assert vite.details.get("findings", 0) > 0
