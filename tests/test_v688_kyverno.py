"""Tests for v6.88.0 KyvernoAnalyzer integration."""

from pathlib import Path

from devai import DevAI, KyvernoAnalyzer
from devai.project_health import ProjectHealth


HARDENED_POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
spec:
  validationFailureAction: Enforce
  failurePolicy: Fail
  background: true
  rules:
    - name: disallow-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: Privileged containers are not allowed
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: false
"""

UNSAFE_POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: weak-policy
spec:
  validationFailureAction: audit
  failurePolicy: Ignore
  background: false
  skipBackgroundRequests: true
  rules:
    - name: allow-anything
      match:
        any:
          - resources:
              kinds:
                - Pod
      exclude:
        any:
          - resources:
              namespaces:
                - "*"
      validate:
        message: weak validation
        pattern:
          spec:
            containers:
              - name: "*"
      mutate:
        patchStrategicMerge:
          spec:
            containers:
              - securityContext:
                  privileged: true
                  allowPrivilegeEscalation: true
                  runAsNonRoot: false
  validationFailureActionOverrides:
    - action: audit
      namespaceSelector: {}
webhook_url: http://insecure.example.com/validate
api_key: supersecret123
"""

EXCEPTION_POLICY = """\
apiVersion: kyverno.io/v1
kind: PolicyException
metadata:
  name: bypass-all
spec:
  exceptions:
    - policyName: "*"
      ruleNames:
        - "*"
"""


class TestKyvernoAnalyzer:
    def test_finds_no_high_issues_in_hardened_policy(self, tmp_path: Path):
        policies = tmp_path / "policies"
        policies.mkdir()
        (policies / "disallow-privileged.yaml").write_text(HARDENED_POLICY, encoding="utf-8")
        analyzer = KyvernoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.policies == 1
        assert analyzer.stats.findings == 0

    def test_detects_unsafe_policy_patterns(self, tmp_path: Path):
        policies = tmp_path / "kyverno"
        policies.mkdir()
        (policies / "weak.yaml").write_text(UNSAFE_POLICY, encoding="utf-8")
        analyzer = KyvernoAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "audit_only" in kinds
        assert "failure_policy_ignore" in kinds
        assert "wildcard_exclude" in kinds
        assert "privileged_mutation" in kinds
        assert "run_as_root" in kinds
        assert "wildcard_match" in kinds
        assert "background_disabled" in kinds
        assert "skip_background" in kinds
        assert "override_audit" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds

    def test_detects_policy_exception(self, tmp_path: Path):
        (tmp_path / "exception.yaml").write_text(EXCEPTION_POLICY, encoding="utf-8")
        analyzer = KyvernoAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "policy_exception" in kinds

    def test_facade_kyverno(self):
        analyzer = DevAI.mock().kyverno(".")
        assert isinstance(analyzer, KyvernoAnalyzer)

    def test_project_health_includes_kyverno_category(self, tmp_path: Path):
        (tmp_path / "policy.yaml").write_text(HARDENED_POLICY, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "kyverno" in names

    def test_generate_hardened_template(self):
        template = KyvernoAnalyzer(".").generate_hardened_template()
        assert "validationFailureAction: Enforce" in template
        assert "failurePolicy: Fail" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "policy.yaml").write_text(HARDENED_POLICY, encoding="utf-8")
        context = KyvernoAnalyzer(str(tmp_path)).to_context()
        assert "Kyverno policy analysis" in context
        assert "health score" in context
