"""Tests for v6.90.0 OPAAnalyzer integration."""

from pathlib import Path

from devai import DevAI, OPAAnalyzer
from devai.project_health import ProjectHealth

HARDENED_POLICY = """\
package example.authz

import rego.v1

default allow := false

allow if {
    input.method == "GET"
    input.path == "/health"
    input.user in data.allowed_users
}

deny contains msg if {
    not input.user
    msg := "authentication required"
}
"""

UNSAFE_POLICY = """\
package example.insecure

default allow = true

allow { true }

allow if {
    glob.match("*", [], input.path)
    http.send({"url": "http://insecure.example.com", "tls_insecure_skip_verify": true})
}

trace("debug")
api_key := "supersecret123"
verify: false
"""

MISSING_DEFAULT_POLICY = """\
package example.partial

allow if {
    input.role == "admin"
}
"""


class TestOPAAnalyzer:
    def test_finds_no_high_issues_in_hardened_policy(self, tmp_path: Path):
        policy = tmp_path / "authz.rego"
        policy.write_text(HARDENED_POLICY, encoding="utf-8")
        analyzer = OPAAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.policies == 1
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_policy(self, tmp_path: Path):
        policy = tmp_path / "insecure.rego"
        policy.write_text(UNSAFE_POLICY, encoding="utf-8")
        analyzer = OPAAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "default_allow_true" in kinds
        assert "unconditional_allow" in kinds
        assert "insecure_tls" in kinds
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.high_severity >= 3
        assert analyzer.health_score() < 50.0

    def test_detects_missing_default_deny(self, tmp_path: Path):
        policy = tmp_path / "partial.rego"
        policy.write_text(MISSING_DEFAULT_POLICY, encoding="utf-8")
        analyzer = OPAAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        missing = [f for f in findings if f.kind == "missing_default_deny"]
        assert len(missing) == 1
        assert missing[0].severity == "medium"

    def test_summary_and_context(self, tmp_path: Path):
        policy = tmp_path / "authz.rego"
        policy.write_text(HARDENED_POLICY, encoding="utf-8")
        analyzer = OPAAnalyzer(str(tmp_path))
        assert "OPA:" in analyzer.summary()
        context = analyzer.to_context()
        assert "OPA policy analysis:" in context
        assert "package=example.authz" in context

    def test_generate_hardened_template(self):
        template = OPAAnalyzer().generate_hardened_template()
        assert "package example.authz" in template
        assert "default allow := false" in template

    def test_devai_facade(self):
        analyzer = DevAI.mock().opa(".")
        assert isinstance(analyzer, OPAAnalyzer)

    def test_project_health_integration(self, tmp_path: Path):
        policy = tmp_path / "authz.rego"
        policy.write_text(HARDENED_POLICY, encoding="utf-8")
        health = ProjectHealth(str(tmp_path), scan_secrets=False)
        report = health.analyze()
        opa_cat = next((c for c in report.categories if c.name == "opa"), None)
        assert opa_cat is not None
        assert opa_cat.score == 100.0
