"""ArgoCDAnalyzer — audit Argo CD Application/ApplicationSet configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ARGOCD_FILENAMES = (
    "application.yaml",
    "application.yml",
    "applicationset.yaml",
    "applicationset.yml",
    "appproject.yaml",
    "appproject.yml",
)
ARGOCD_DIRS = (".argocd", "argocd", "apps", "applications", "manifests/argocd", "deploy/argocd")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*\n"
    r"\s*value\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE | re.MULTILINE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repoURL|url)\s*:\s*http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
ARGOCD_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*argoproj\.io/v\d",
    re.IGNORECASE,
)
WILDCARD_NAMESPACE_PATTERN = re.compile(
    r"namespace\s*:\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
WILDCARD_SERVER_PATTERN = re.compile(
    r"server\s*:\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
CLUSTER_DESTINATION_PATTERN = re.compile(
    r"server\s*:\s*https://kubernetes\.default\.svc",
    re.IGNORECASE,
)
INSECURE_SKIP_VERIFY_PATTERN = re.compile(
    r"(?:insecure\s*:\s*true|insecureSkipTLSVerify\s*:\s*true|skipServerVerification\s*:\s*true)",
    re.IGNORECASE,
)
ALLOW_EMPTY_PATTERN = re.compile(
    r"allowEmpty\s*:\s*true",
    re.IGNORECASE,
)
ORPHANED_RESOURCES_PATTERN = re.compile(
    r"orphanedResources\s*:\s*\{\s*\}",
    re.IGNORECASE,
)
AUTO_SYNC_NO_PRUNE_PATTERN = re.compile(
    r"automated\s*:\s*\{[^}]*\}",
    re.IGNORECASE | re.DOTALL,
)
PRUNE_DISABLED_PATTERN = re.compile(
    r"prune\s*:\s*false",
    re.IGNORECASE,
)
SELF_HEAL_DISABLED_PATTERN = re.compile(
    r"selfHeal\s*:\s*false",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:targetRevision|tag|version)\s*:\s*(?:latest|HEAD|main|master)\b",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|clusterrolebinding.*cluster-admin",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\{\{\s*(?:\.Values|\.path|\.repo|\.url|\.branch|\.name|\.namespace)[^}]+\}\}",
    re.IGNORECASE,
)
CREDENTIALS_IN_URL_PATTERN = re.compile(
    r"(?:repoURL|url)\s*:\s*https?://[^:@\s\"']+:[^@\s\"']+@",
    re.IGNORECASE,
)
OCI_INSECURE_PATTERN = re.compile(
    r"(?:enableOCI|oci)\s*:\s*true",
    re.IGNORECASE,
)
SOURCE_NAMESPACE_WILDCARD_PATTERN = re.compile(
    r"sourceNamespaces\s*:\s*\n\s*-\s*[\"']?\*[\"']?",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class ArgoCDFinding:
    """A security or best-practice issue in an Argo CD config."""

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
class ArgoCDInfo:
    """Parsed metadata about an Argo CD config file."""

    path: str
    kind: str = ""
    apps: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class ArgoCDStats:
    """Aggregate Argo CD analysis statistics."""

    applications: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_argocd_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in ARGOCD_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(ARGOCD_DIRS):
        if lower.endswith((".yml", ".yaml")):
            return True
    if lower.endswith(".argocd.yaml") or lower.endswith(".argocd.yml"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
        if ARGOCD_API_PATTERN.search(head):
            if re.search(
                r"kind\s*:\s*(?:Application|ApplicationSet|AppProject)\b",
                head,
                re.IGNORECASE,
            ):
                return True
    except OSError:
        pass
    return False


class ArgoCDAnalyzer:
    """Audit Argo CD Applications for insecure sources, wildcards, and weak sync policies.

    Scans Application, ApplicationSet, and AppProject YAML for hardcoded secrets,
    HTTP git repos, wildcard destinations, disabled prune/selfHeal, and credentials
    embedded in repo URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ArgoCDFinding] | None = None
        self._stats: ArgoCDStats | None = None
        self._infos: list[ArgoCDInfo] | None = None

    def files(self) -> list[Path]:
        """Return Argo CD config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_argocd_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ArgoCDFinding], ArgoCDInfo]:
        findings: list[ArgoCDFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, ArgoCDInfo(path=rel)

        info = ArgoCDInfo(path=rel, lines=len(raw_lines))
        has_automated = "automated:" in content or "automated: {}" in content.replace(" ", "")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = re.match(r"^\s*kind\s*:\s*(.+)$", raw, re.I)
            if kind_match:
                info.kind = kind_match.group(1).strip().strip("\"'")

            name_match = re.match(r"^\s*name\s*:\s*(.+)$", raw)
            if name_match and info.kind in ("Application", "ApplicationSet"):
                info.apps.append(name_match.group(1).strip().strip("\"'"))

            if "namespace:" in raw and "destination:" in content:
                ns_match = re.search(r"namespace\s*:\s*(.+)$", raw, re.I)
                if ns_match:
                    info.destinations.append(ns_match.group(1).strip().strip("\"'"))

            if INSECURE_HTTP_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="insecure HTTP git/OCI source URL",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CREDENTIALS_IN_URL_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="credentials_in_url",
                        severity="critical",
                        message="credentials embedded in repository URL",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret value in manifest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_SECRET_VALUE_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="plaintext_token",
                        severity="critical",
                        message="plaintext API token or credential detected",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_SKIP_VERIFY_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="insecure_skip_tls",
                        severity="high",
                        message="TLS verification disabled for git/OCI source",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_NAMESPACE_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="wildcard_namespace",
                        severity="high",
                        message="wildcard namespace destination allows deploying to any namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_SERVER_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="wildcard_server",
                        severity="high",
                        message="wildcard server destination allows deploying to any cluster",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_EMPTY_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="allow_empty_sync",
                        severity="medium",
                        message="allowEmpty sync policy can delete all resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRUNE_DISABLED_PATTERN.search(raw) and has_automated:
                findings.append(
                    ArgoCDFinding(
                        kind="prune_disabled",
                        severity="medium",
                        message="automated sync with prune disabled leaves orphaned resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SELF_HEAL_DISABLED_PATTERN.search(raw) and has_automated:
                findings.append(
                    ArgoCDFinding(
                        kind="self_heal_disabled",
                        severity="low",
                        message="automated sync with selfHeal disabled allows configuration drift",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="unpinned_revision",
                        severity="medium",
                        message="unpinned targetRevision or image tag (latest/HEAD)",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="cluster_admin_rbac",
                        severity="high",
                        message="cluster-admin RBAC binding detected",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(raw):
                findings.append(
                    ArgoCDFinding(
                        kind="template_injection",
                        severity="medium",
                        message="ApplicationSet template variable in sensitive field",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SOURCE_NAMESPACE_WILDCARD_PATTERN.search(content) and lineno == 1:
                findings.append(
                    ArgoCDFinding(
                        kind="wildcard_source_namespace",
                        severity="high",
                        message="AppProject allows applications from any source namespace",
                        path=rel,
                        lineno=lineno,
                        line="sourceNamespaces: ['*']",
                    )
                )

        if HARDCODED_ENV_VALUE_PATTERN.search(content):
            for match in HARDCODED_ENV_VALUE_PATTERN.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    ArgoCDFinding(
                        kind="hardcoded_env_secret",
                        severity="high",
                        message="secret value in environment variable block",
                        path=rel,
                        lineno=line_no,
                        line=match.group(0).splitlines()[0],
                    )
                )

        return findings, info

    def analyze(self) -> list[ArgoCDFinding]:
        """Scan Argo CD configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ArgoCDFinding] = []
        infos: list[ArgoCDInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity in ("high", "critical"))
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = ArgoCDStats(
            applications=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ArgoCDStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ArgoCDInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no applications)."""
        self.analyze()
        stats = self.stats
        if stats.applications == 0:
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
        """Scaffold a hardened Argo CD Application manifest."""
        return """\
# Generated by DevAI ArgoCDAnalyzer
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: app
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/org/app.git
    targetRevision: v1.2.3
    path: deploy
  destination:
    server: https://kubernetes.default.svc
    namespace: app
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - PrunePropagationPolicy=foreground
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.applications == 0:
            return "Argo CD applications: none found"
        return (
            f"Argo CD applications: {stats.applications} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Argo CD analysis:",
            f"  applications: {stats.applications}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: kind={info.kind or 'unknown'}, "
                f"{len(info.apps)} app(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
