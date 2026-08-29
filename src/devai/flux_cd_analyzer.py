"""FluxCDAnalyzer — audit Flux CD GitOps configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FLUX_FILENAMES = (
    "gitrepository.yaml",
    "gitrepository.yml",
    "helmrepository.yaml",
    "helmrepository.yml",
    "kustomization.yaml",
    "kustomization.yml",
    "helmrelease.yaml",
    "helmrelease.yml",
    "ocirepository.yaml",
    "ocirepository.yml",
)
FLUX_DIRS = (".flux", "flux", "clusters", "infrastructure", "manifests/flux")

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:tag|version|image)[^\n]*:latest\b",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"url\s*:\s*http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
FLUX_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*(?:source|kustomize|helm|notification|image)\.toolkit\.fluxcd\.io/",
    re.IGNORECASE,
)
INSECURE_SKIP_TLS_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|insecure_skip_tls_verify)\s*:\s*true",
    re.IGNORECASE,
)
VERIFY_DISABLED_PATTERN = re.compile(
    r"(?:verify|signatureVerification)\s*:\s*(?:false|none|disabled)",
    re.IGNORECASE,
)
FORCE_APPLY_PATTERN = re.compile(
    r"force\s*:\s*true",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|clusterrolebinding.*cluster-admin",
    re.IGNORECASE,
)
PRUNE_DISABLED_PATTERN = re.compile(
    r"prune\s*:\s*false",
    re.IGNORECASE,
)
WAIT_DISABLED_PATTERN = re.compile(
    r"(?:wait|disableWait)\s*:\s*(?:false|true)",
    re.IGNORECASE,
)
INSECURE_HELM_REPO_PATTERN = re.compile(
    r"url\s*:\s*http://[^\s\"']+",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)


@dataclass
class FluxCDFinding:
    """A security or best-practice issue in a Flux CD config."""

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
class FluxCDInfo:
    """Parsed metadata about a Flux CD config file."""

    path: str
    kind: str = ""
    resources: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class FluxCDStats:
    """Aggregate Flux CD analysis statistics."""

    manifests: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_flux_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in FLUX_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(FLUX_DIRS):
        if lower.endswith((".yml", ".yaml")):
            return True
    if lower.endswith(".flux.yaml") or lower.endswith(".flux.yml"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
        if FLUX_API_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class FluxCDAnalyzer:
    """Audit Flux CD GitOps configs for hardcoded secrets, insecure sources, and weak defaults.

    Scans GitRepository, HelmRepository, Kustomization, and HelmRelease YAML for
    HTTP git URLs, disabled TLS verification, force apply, cluster-admin RBAC,
  and secrets in spec blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FluxCDFinding] | None = None
        self._stats: FluxCDStats | None = None
        self._infos: list[FluxCDInfo] | None = None

    def files(self) -> list[Path]:
        """Return Flux CD config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_flux_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[FluxCDFinding], FluxCDInfo]:
        findings: list[FluxCDFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, FluxCDInfo(path=rel)

        info = FluxCDInfo(path=rel, lines=len(raw_lines))
        in_security_resource = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = re.match(r"^\s*kind\s*:\s*(.+)$", raw, re.I)
            if kind_match:
                info.kind = kind_match.group(1).strip().strip("\"'")
                in_security_resource = bool(SECURITY_STEP_PATTERN.search(info.kind))

            name_match = re.match(r"^\s*name\s*:\s*(.+)$", raw, re.I)
            if name_match and "metadata:" in content:
                resource_name = name_match.group(1).strip().strip("\"'")
                if resource_name and resource_name not in info.resources:
                    info.resources.append(resource_name)
                    in_security_resource = bool(SECURITY_STEP_PATTERN.search(resource_name))

            url_match = re.match(r"^\s*url\s*:\s*(.+)$", raw, re.I)
            if url_match:
                url = url_match.group(1).strip().strip("\"'")
                info.sources.append(url)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="hardcoded_secret",
                        severity="critical",
                        message="hardcoded secret in Flux manifest — use Kubernetes secrets or SOPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="plaintext_token",
                        severity="critical",
                        message="plaintext API token or credential detected",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_ENV_VALUE_PATTERN.search(content):
                if re.match(r"^\s*value\s*:", raw, re.I):
                    findings.append(
                        FluxCDFinding(
                            kind="hardcoded_env_secret",
                            severity="high",
                            message="secret value hardcoded in env block — use secretKeyRef",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="git or helm source uses insecure HTTP URL",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HELM_REPO_PATTERN.search(line) and "helm" in line.lower():
                findings.append(
                    FluxCDFinding(
                        kind="insecure_helm_repo",
                        severity="high",
                        message="Helm repository uses insecure HTTP URL",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_SKIP_TLS_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="insecure_skip_tls",
                        severity="high",
                        message="TLS verification is disabled for a git or OCI source",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if VERIFY_DISABLED_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="verify_disabled",
                        severity="high",
                        message="commit or chart signature verification is disabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FORCE_APPLY_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="force_apply",
                        severity="high",
                        message="force: true can overwrite fields managed by other controllers",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="cluster_admin_rbac",
                        severity="critical",
                        message="cluster-admin RBAC binding grants full cluster access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="unpinned :latest image or chart tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRUNE_DISABLED_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="prune_disabled",
                        severity="medium",
                        message="prune: false allows orphaned resources to accumulate",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.search(r"disableWait\s*:\s*true", line, re.I):
                findings.append(
                    FluxCDFinding(
                        kind="wait_disabled",
                        severity="medium",
                        message="disableWait: true skips readiness checks before marking sync successful",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    FluxCDFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in postBuild or substitution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_resource and WAIT_DISABLED_PATTERN.search(line):
                if re.search(r"wait\s*:\s*false", line, re.I):
                    findings.append(
                        FluxCDFinding(
                            kind="skip_security_wait",
                            severity="high",
                            message="security resource configured to skip readiness wait",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[FluxCDFinding]:
        """Scan Flux CD configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FluxCDFinding] = []
        infos: list[FluxCDInfo] = []
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
        self._stats = FluxCDStats(
            manifests=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FluxCDStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FluxCDInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
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
        """Scaffold a hardened Flux CD GitOps layout."""
        return """\
# Generated by DevAI FluxCDAnalyzer
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: app-source
  namespace: flux-system
spec:
  interval: 5m
  url: https://github.com/org/app.git
  ref:
    branch: main
  secretRef:
    name: git-credentials
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: app-source
  path: ./deploy
  prune: true
  wait: true
  timeout: 5m
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: app
  namespace: flux-system
spec:
  interval: 30m
  chart:
    spec:
      chart: app
      version: "1.2.3"
      sourceRef:
        kind: HelmRepository
        name: app-charts
  values:
    image:
      tag: "1.2.3"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Flux CD manifests: none found"
        return (
            f"Flux CD manifests: {stats.manifests} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Flux CD analysis:",
            f"  manifests: {stats.manifests}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: kind={info.kind or 'unknown'}, "
                f"{len(info.resources)} resource(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
