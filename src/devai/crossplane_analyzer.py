"""CrossplaneAnalyzer — audit Crossplane Kubernetes manifests for security misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CROSSPLANE_SUFFIXES = (".yaml", ".yml")
CROSSPLANE_DIRS = ("crossplane", "compositions", "xrds", "providers", "claims", "manifests/crossplane")
CROSSPLANE_FILENAMES = (
    "provider.yaml",
    "provider.yml",
    "providerconfig.yaml",
    "providerconfig.yml",
    "composition.yaml",
    "composition.yml",
    "xrd.yaml",
    "xrd.yml",
)
CROSSPLANE_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*[\w.-]*crossplane\.io/",
    re.IGNORECASE,
)
CROSSPLANE_KIND_PATTERN = re.compile(
    r"kind\s*:\s*(?:Provider|ProviderConfig|Composition|CompositeResourceDefinition|"
    r"Configuration|Function|DeploymentRuntimeConfig|EnvironmentConfig|Usage)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|package|source|registry)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SKIP_TLS_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|insecure_skip_tls_verify|skipTLSVerify)\s*:\s*true",
    re.IGNORECASE,
)
UNVERSIONED_PROVIDER_PATTERN = re.compile(
    r"^\s*package\s*:\s*[\"']?[^\"'\s]+[\"']?\s*$",
    re.IGNORECASE,
)
PROVIDER_VERSION_PATTERN = re.compile(
    r"^\s*(?:package|version)\s*:",
    re.IGNORECASE,
)
WILDCARD_IAM_PATTERN = re.compile(
    r"(?:Action|Resource|actions|resources)\s*:\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
OPEN_SG_PATTERN = re.compile(r"0\.0\.0\.0/0|::/0")
PUBLIC_ACCESS_PATTERN = re.compile(
    r"(?:publiclyAccessible|publicly_accessible|publicAccess|public_access)\s*:\s*true",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged|allowPrivilegeEscalation)\s*:\s*true",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser|runAsNonRoot)\s*:\s*(?:0|false)",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|clusterrolebinding.*cluster-admin",
    re.IGNORECASE,
)
DELETION_POLICY_DELETE_PATTERN = re.compile(
    r"(?:deletionPolicy|deletion_policy)\s*:\s*Delete",
    re.IGNORECASE,
)
PLAINTEXT_CREDENTIALS_PATTERN = re.compile(
    r"(?:credentials|awsSecretAccessKey|secretAccessKey)\s*:\s*"
    r"(?:[\"'][^\"'{}\s][^\"']+[\"']|(?!\!|\{)[^\s#]+)",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|package)\s*:\s*[\"'][^\"']*:latest[\"']",
    re.IGNORECASE,
)
WRITE_CONNECTION_SECRET_PATTERN = re.compile(
    r"writeConnectionSecretToRef\s*:\s*\n\s+namespace\s*:\s*(?:default|kube-system)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class CrossplaneFinding:
    """A security or best-practice issue in a Crossplane manifest."""

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
class CrossplaneInfo:
    """Parsed metadata about a Crossplane manifest file."""

    path: str
    kind: str = ""
    api_version: str = ""
    resources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CrossplaneStats:
    """Aggregate Crossplane analysis statistics."""

    manifests: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_crossplane_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CROSSPLANE_FILENAMES:
        return True
    if lower.endswith(CROSSPLANE_SUFFIXES):
        parts = {p.lower() for p in path.parts}
        if parts & set(CROSSPLANE_DIRS):
            return True
        if lower.endswith((".crossplane.yaml", ".crossplane.yml")):
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if CROSSPLANE_API_PATTERN.search(head) or CROSSPLANE_KIND_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class CrossplaneAnalyzer:
    """Audit Crossplane Kubernetes manifests for hardcoded secrets and insecure configs.

    Scans Provider, ProviderConfig, Composition, and XRD YAML for plaintext credentials,
    HTTP package sources, disabled TLS verification, unversioned providers, wildcard IAM,
    open security groups, privileged containers, and risky deletion policies.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[CrossplaneFinding] | None = None
        self._stats: CrossplaneStats | None = None
        self._infos: list[CrossplaneInfo] | None = None

    def files(self) -> list[Path]:
        """Return Crossplane manifest files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_crossplane_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CrossplaneFinding], CrossplaneInfo]:
        findings: list[CrossplaneFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CrossplaneInfo(path=rel)

        text = "\n".join(raw_lines)
        info = CrossplaneInfo(path=rel, lines=len(raw_lines))

        api_match = re.search(r"^\s*apiVersion\s*:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
        if api_match:
            info.api_version = api_match.group(1).strip("\"'")

        kind_match = re.search(r"^\s*kind\s*:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
        if kind_match:
            info.kind = kind_match.group(1).strip("\"'")

        has_package = False
        has_version = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            resource_match = re.search(
                r"(?:name|resourceName)\s*:\s*[\"']?([\w.-]+)[\"']?",
                stripped,
                re.IGNORECASE,
            )
            if resource_match:
                resource = resource_match.group(1)
                if resource not in info.resources:
                    info.resources.append(resource)

            if PROVIDER_VERSION_PATTERN.search(stripped):
                if re.search(r"^\s*package\s*:", stripped, re.IGNORECASE):
                    has_package = True
                if re.search(r"^\s*version\s*:", stripped, re.IGNORECASE):
                    has_version = True

            if AWS_ACCESS_KEY_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use IRSA or ProviderConfig secret references",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Crossplane manifest — use Kubernetes Secrets or external secret stores",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PLAINTEXT_CREDENTIALS_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="plaintext_credentials",
                        severity="high",
                        message="plaintext credentials in ProviderConfig — reference a Kubernetes Secret instead",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="provider package fetched over HTTP — use HTTPS OCI or xpkg.upbound.io registry",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SKIP_TLS_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="skip_tls_verify",
                        severity="high",
                        message="TLS verification disabled — enable certificate validation for provider packages",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if WILDCARD_IAM_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="wildcard_iam",
                        severity="high",
                        message="wildcard IAM Action or Resource — apply least-privilege permissions",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if OPEN_SG_PATTERN.search(stripped) and (
                "cidr" in stripped.lower()
                or "ingress" in stripped.lower()
                or "security" in stripped.lower()
            ):
                findings.append(
                    CrossplaneFinding(
                        kind="open_security_group",
                        severity="high",
                        message="security group allows 0.0.0.0/0 — restrict to specific CIDR ranges",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PUBLIC_ACCESS_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="public_access",
                        severity="high",
                        message="publicly accessible resource — restrict to private subnets or VPC",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PRIVILEGED_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container in composition — drop privileges for managed workloads",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if ROOT_USER_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot: true and a non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin RBAC binding — use namespace-scoped roles with least privilege",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if DELETION_POLICY_DELETE_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="deletion_policy_delete",
                        severity="medium",
                        message="deletionPolicy: Delete on managed resource — use Orphan for production data resources",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LATEST_TAG_PATTERN.search(stripped):
                findings.append(
                    CrossplaneFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="unpinned :latest image or package tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if WRITE_CONNECTION_SECRET_PATTERN.search(text):
            match = WRITE_CONNECTION_SECRET_PATTERN.search(text)
            if match:
                line_no = text[: match.start()].count("\n") + 1
                findings.append(
                    CrossplaneFinding(
                        kind="connection_secret_namespace",
                        severity="low",
                        message="connection secret written to default/kube-system namespace — use a dedicated namespace",
                        path=rel,
                        lineno=line_no,
                        line="",
                    )
                )

        if info.kind == "Provider" and has_package and not has_version:
            findings.append(
                CrossplaneFinding(
                    kind="unversioned_provider",
                    severity="medium",
                    message="Provider package without version pin — pin provider version for reproducible deployments",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[CrossplaneFinding]:
        """Scan Crossplane manifest files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CrossplaneFinding] = []
        infos: list[CrossplaneInfo] = []
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
        self._stats = CrossplaneStats(
            manifests=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CrossplaneStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CrossplaneInfo]:
        """Return parsed manifest metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
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
        """Scaffold a hardened Crossplane Provider and ProviderConfig template."""
        return """\
# Hardened Crossplane Provider template
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  package: xpkg.upbound.io/upbound/provider-aws-ec2:v1.14.0
  packagePullPolicy: IfNotPresent
  revisionActivationPolicy: Automatic
  revisionHistoryLimit: 1
---
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: default
spec:
  credentials:
    source: IRSA
  # Use IRSA or secretRef — never embed credentials inline:
  # credentials:
  #   source: Secret
  #   secretRef:
  #     name: aws-creds
  #     namespace: crossplane-system
  #     key: creds
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return "Crossplane: none found"
        return (
            f"Crossplane: {stats.manifests} manifest(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Crossplane manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: kind={info.kind or 'n/a'}, "
                f"apiVersion={info.api_version or 'n/a'}, "
                f"resources={info.resources or 'none'}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
