"""Tests for StarlightAnalyzer."""

from pathlib import Path

from devai.starlight_analyzer import StarlightAnalyzer, StarlightFinding


INSECURE_STARLIGHT = """\
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const apiSecret = 'sk-live-hardcoded-secret-key';

export default defineConfig({
  integrations: [
    starlight({
      title: 'Demo Docs',
      favicon: 'http://insecure.example.com/favicon.ico',
      social: {
        github: 'https://user:secretpass@github.com/org/repo',
      },
      editLink: {
        baseUrl: 'http://insecure.example.com/edit/',
      },
      customCss: ['https://cdn.example.com/theme.css'],
      head: [
        { tag: 'script', attrs: { src: 'https://cdn.example.com/analytics.js' } },
      ],
      expressiveCode: {
        allowDangerousHtml: true,
      },
      components: {
        Header: 'https://evil.example.com/header.js',
      },
      routeMiddleware: ['./middleware.ts', 'eval("bad")'],
      defaultLocale: '*',
    }),
  ],
});
"""

HARDENED_STARLIGHT = """\
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  integrations: [
    starlight({
      title: 'Demo Docs',
      favicon: '/favicon.svg',
      social: {
        github: 'https://github.com/org/repo',
      },
      editLink: {
        baseUrl: 'https://github.com/org/repo/edit/main/',
      },
      customCss: ['./src/styles/custom.css'],
      head: [],
      defaultLocale: 'en',
    }),
  ],
});
"""


class TestStarlightAnalyzer:
    def test_detects_insecure_starlight_config(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(INSECURE_STARLIGHT, encoding="utf-8")
        analyzer = StarlightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "credential_in_url" in kinds
        assert "edit_link_http" in kinds
        assert "remote_head_script" in kinds
        assert "expressive_code_unsafe" in kinds
        assert "components_remote" in kinds
        assert "route_middleware_unsafe" in kinds
        assert "favicon_http" in kinds
        assert "default_locale_wildcard" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_starlight_scores_well(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(HARDENED_STARLIGHT, encoding="utf-8")
        analyzer = StarlightAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = StarlightAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_ignores_non_starlight_astro_config(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(
            "import { defineConfig } from 'astro/config';\nexport default defineConfig({});\n",
            encoding="utf-8",
        )
        analyzer = StarlightAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []

    def test_generate_hardened_template(self):
        template = StarlightAnalyzer(".").generate_hardened_template()
        assert "@astrojs/starlight" in template
        assert "editLink" in template
        assert "head: []" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "astro.config.mjs").write_text(INSECURE_STARLIGHT, encoding="utf-8")
        analyzer = StarlightAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "Starlight analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = StarlightFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="astro.config.mjs",
            lineno=5,
            line="apiSecret = 'x'",
        )
        assert "[high]" in finding.format()
        assert "astro.config.mjs:5" in finding.format()
