"""KyvernoAnalyzer — audit Kyverno Kubernetes policy manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

KYVERNO_API_PATTERN = re.compile(r"^\s*apiVersion\s*:\s*kyverno\.io/", re.IGNORECASE | re.MULTILINE)
KYVERNO_KIND_PATTERN = re.compile(
    r"^\s*kind\s*:\s*(?:ClusterPolicy|Policy|ClusterCleanupPolicy|CleanupPolicy|"
    r"PolicyException|ClusterPolicyException|ValidatingPolicy|MutatingPolicy|ImageValidatingPolicy)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|xox[baprs]-)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
AUDIT_ACTION_PATTERN = re.compile(
    r"^\s*validationFailureAction\s*:\s*audit\s*$",
    re.IGNORECASE,
)
ENFORCE_OVERRIDE_AUDIT_PATTERN = re.compile(
    r"^\s*(?:-\s*)?action\s*:\s*audit\s*$",
    re.IGNORECASE,
)
FAILURE_POLICY_IGNORE_PATTERN = re.compile(
    r"^\s*failurePolicy\s*:\s*Ignore\s*$",
    re.IGNORECASE,
)
BACKGROUND_FALSE_PATTERN = re.compile(
    r"^\s*background\s*:\s*false\s*$",
    re.IGNORECASE,
)
SKIP_BACKGROUND_PATTERN = re.compile(
    r"^\s*skipBackgroundRequests\s*:\s*true\s*$",
    re.IGNORECASE,
)
BROAD_EXCLUDE_NAMESPACE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
)
BROAD_EXCLUDE_KEY_PATTERN = re.compile(
    r"^\s*(?:namespaces|names|kinds|resources|subjects)\s*:\s*$",
    re.IGNORECASE,
)
PRIVILEGED_MUTATION_PATTERN = re.compile(
    r"^\s*(?:privileged|allowPrivilegeEscalation|hostPID|hostNetwork|hostIPC)\s*:\s*true\s*$",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*runAsNonRoot\s*:\s*false\s*$",
    re.IGNORECASE,
)
WILDCARD_MATCH_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:pattern|value|name)\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|endpoint|registry|api|server)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
DISABLED_VERIFY_PATTERN = re.compile(
    r"^\s*(?:verifyImages|mutate|validate|generate)\s*:\s*(?:\[\s*\]|null|none)\s*$",
    re.IGNORECASE,
)
SYNC_GENERATE_PATTERN = re.compile(
    r"^\s*synchronize\s*:\s*true\s*$",
    re.IGNORECASE,
)
EXCEPTION_POLICY_PATTERN = re.compile(
    r"^\s*kind\s*:\s*(?:PolicyException|ClusterPolicyException)\s*$",
    re.IGNORECASE,
)
BROAD_EXCEPTION_MATCH_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
)


@dataclass
class KyvernoFinding:
    """A security or best-practice issue in a Kyverno policy manifest."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class KyvernoInfo:
    """Parsed metadata about a Kyverno policy file."""

    path: str
    policy_kind: str = ""
    rule_count: int = 0
    exclude_count: int = 0
    is_exception: bool = False
    lines: int = 0


@dataclass
class KyvernoStats:
    """Aggregate Kyverno analysis statistics."""

    policies: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_kyverno_file(path: Path) -> bool:
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(KYVERNO_API_PATTERN.search(text) and KYVERNO_KIND_PATTERN.search(text))


class KyvernoAnalyzer:
    """Audit Kyverno policy manifests for audit-only enforcement, broad excludes, and unsafe mutations.

    Scans YAML manifests containing ``apiVersion: kyverno.io/*`` for validationFailureAction: audit,
    failurePolicy: Ignore, wildcard namespace excludes, privileged mutations, and policy exceptions.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[KyvernoFinding] | None = None
        self._stats: KyvernoStats | None = None
        self._infos: list[KyvernoInfo] | None = None

    def files(self) -> list[Path]:
        """Return Kyverno policy files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_kyverno_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[KyvernoFinding], KyvernoInfo]:
        findings: list[KyvernoFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KyvernoInfo(path=rel)

        info = KyvernoInfo(path=rel, lines=len(raw_lines))
        in_exclude_block = False
        in_namespaces_block = False
        in_override_block = False
        in_rules_block = False
        policy_kind = ""

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            kind_match = re.search(r"^\s*kind\s*:\s*(\S+)", line, re.IGNORECASE)
            if kind_match:
                policy_kind = kind_match.group(1)
                info.policy_kind = policy_kind
                if EXCEPTION_POLICY_PATTERN.search(line):
                    info.is_exception = True
                    findings.append(
                        KyvernoFinding(
                            kind="policy_exception",
                            severity="medium",
                            message="PolicyException bypasses Kyverno enforcement — scope narrowly and review regularly",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if re.search(r"^\s*rules\s*:", line, re.IGNORECASE):
                in_rules_block = True
            elif re.search(r"^\s*exclude\s*:", line, re.IGNORECASE):
                in_exclude_block = True
                in_namespaces_block = False
            elif re.search(r"^\s*namespaces\s*:", line, re.IGNORECASE) and in_exclude_block:
                in_namespaces_block = True
            elif re.search(r"^\s*validationFailureActionOverrides\s*:", line, re.IGNORECASE):
                in_override_block = True
            elif re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                if re.search(r"^\s*exclude\s*:", line, re.IGNORECASE):
                    pass
                elif in_namespaces_block and not re.search(r"^\s*namespaces\s*:", line, re.IGNORECASE):
                    in_namespaces_block = False
                elif in_exclude_block and not re.search(r"^\s*exclude\s*:", line, re.IGNORECASE):
                    if not re.search(r"^\s*(?:any|all|resources)\s*:", line, re.IGNORECASE):
                        in_exclude_block = False
                if in_override_block and not re.search(
                    r"^\s*validationFailureActionOverrides\s*:", line, re.IGNORECASE
                ):
                    in_override_block = False

            if in_rules_block and re.match(r"^\s*-\s*name\s*:", line):
                info.rule_count += 1

            if in_namespaces_block and BROAD_EXCLUDE_NAMESPACE_PATTERN.match(stripped):
                info.exclude_count += 1
                findings.append(
                    KyvernoFinding(
                        kind="wildcard_exclude",
                        severity="high",
                        message="wildcard namespace exclude disables Kyverno policy for all namespaces — scope excludes narrowly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif in_exclude_block and BROAD_EXCLUDE_NAMESPACE_PATTERN.match(stripped):
                info.exclude_count += 1
                findings.append(
                    KyvernoFinding(
                        kind="wildcard_exclude",
                        severity="high",
                        message="wildcard exclude disables Kyverno policy for all resources — scope excludes narrowly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif info.is_exception and BROAD_EXCEPTION_MATCH_PATTERN.match(stripped):
                findings.append(
                    KyvernoFinding(
                        kind="broad_exception",
                        severity="high",
                        message="wildcard PolicyException match bypasses policy enforcement broadly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_override_block and ENFORCE_OVERRIDE_AUDIT_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="override_audit",
                        severity="medium",
                        message="validationFailureActionOverrides set to audit — violations will not block admission",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AUDIT_ACTION_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="audit_only",
                        severity="high",
                        message="validationFailureAction: audit — policy violations are logged but not blocked",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FAILURE_POLICY_IGNORE_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="failure_policy_ignore",
                        severity="high",
                        message="failurePolicy: Ignore — Kyverno errors will not block admission requests",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BACKGROUND_FALSE_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="background_disabled",
                        severity="medium",
                        message="background: false — existing resources will not be scanned or remediated",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_BACKGROUND_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="skip_background",
                        severity="low",
                        message="skipBackgroundRequests enabled — background reconciliation may be incomplete",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_MUTATION_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="privileged_mutation",
                        severity="high",
                        message="mutation enables privileged/host access — review patch for container escape risk",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="run_as_root",
                        severity="medium",
                        message="runAsNonRoot: false — policy allows containers to run as root",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_MATCH_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="wildcard_match",
                        severity="medium",
                        message="wildcard pattern/value matches all inputs — tighten validation criteria",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Kyverno policy — use Kubernetes Secrets or external secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="hardcoded token in Kyverno policy — use Secret references instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP endpoint in Kyverno policy — use HTTPS for webhooks and registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SYNC_GENERATE_PATTERN.search(line):
                findings.append(
                    KyvernoFinding(
                        kind="synchronize_generate",
                        severity="low",
                        message="synchronize: true on generate rule — ensure generated resources cannot be tampered with",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if info.rule_count == 0 and policy_kind and not info.is_exception:
            findings.append(
                KyvernoFinding(
                    kind="empty_rules",
                    severity="low",
                    message="Kyverno policy has no rules — add validation, mutation, or generation rules",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        return findings, info

    def analyze(self) -> list[KyvernoFinding]:
        """Scan Kyverno policy manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KyvernoFinding] = []
        infos: list[KyvernoInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = KyvernoStats(
            policies=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> KyvernoStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[KyvernoInfo]:
        """Return parsed policy metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no policies)."""
        self.analyze()
        stats = self.stats
        if stats.policies == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Kyverno ClusterPolicy template."""
        return """\
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

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.policies == 0:
            return "Kyverno: none found"
        return (
            f"Kyverno: {stats.policies} policy file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kyverno policy analysis:",
            f"  policies: {stats.policies}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: kind={info.policy_kind}, rules={info.rule_count}, "
                f"excludes={info.exclude_count}, exception={info.is_exception}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
