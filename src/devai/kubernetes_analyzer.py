"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_EXTENSIONS = (".yaml", ".yml")
K8S_DIR_NAMES = ("k8s", "kubernetes", "manifests", "deploy", "deployment")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_CONTENT_PATTERN = re.compile(
    r"add:\s*\n\s*-\s*ALL\b",
    re.IGNORECASE | re.MULTILINE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|\btoken\b|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(r"^\s*hostPath:\s*", re.IGNORECASE)
DANGEROUS_HOST_PATH_PATTERN = re.compile(
    r"hostPath:\s*\n\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run)['\"]?",
    re.IGNORECASE | re.MULTILINE,
)
AUTOMOUNT_TRUE_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken:\s*true\b",
    re.IGNORECASE,
)
DEFAULT_NAMESPACE_PATTERN = re.compile(
    r"^\s*namespace:\s*['\"]?default['\"]?\s*$",
    re.IGNORECASE,
)
SECRET_IN_ENV_VALUE_PATTERN = re.compile(
    r"^\s*-\s*name:\s*\w+\s*\n\s*value:\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    resource: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    resources: list[str] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in K8S_EXTENSIONS:
        return False
    name_lower = path.name.lower()
    if any(part in path.parts for part in K8S_DIR_NAMES):
        return True
    k8s_markers = (
        "deployment",
        "service",
        "ingress",
        "configmap",
        "secret",
        "pod",
        "daemonset",
        "statefulset",
        "namespace",
        "cronjob",
        "job",
        "helm",
    )
    return any(marker in name_lower for marker in k8s_markers)


class KubernetesAnalyzer:
    """Audit Kubernetes YAML manifests for security risks and best practices.

    Scans for privileged mode, host namespaces, :latest image tags, secrets in
    environment values, dangerous hostPath mounts, missing runAsNonRoot, and
    automountServiceAccountToken misuse.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._infos: list[KubernetesInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        current_resource = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                current_resource = kind
                info.resources.append(kind)
                continue

            if line.startswith("metadata:"):
                continue

            if line.startswith("name:") and current_resource:
                name = line.split(":", 1)[1].strip().strip("'\"")
                current_resource = f"{current_resource}/{name}"

            if line.startswith("namespace:"):
                ns = line.split(":", 1)[1].strip().strip("'\"")
                if ns not in info.namespaces:
                    info.namespaces.append(ns)
                if DEFAULT_NAMESPACE_PATTERN.match(raw):
                    findings.append(
                        KubernetesFinding(
                            kind="default_namespace",
                            severity="low",
                            message="resource in default namespace — use dedicated namespaces",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

            if line == "securityContext:" or line.startswith("securityContext:"):
                continue

            if RUN_AS_NON_ROOT_FALSE_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="run_as_non_root_false",
                        severity="high",
                        message="runAsNonRoot: false allows root container execution",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )
            elif re.match(r"^\s*runAsNonRoot:\s*true\b", raw, re.IGNORECASE):
                pass

            if PRIVILEGED_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true shares host network namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_PID_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares host process namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_IPC_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="allow_privilege_escalation",
                        severity="high",
                        message="allowPrivilegeEscalation: true enables privilege escalation",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if SECRET_ENV_PATTERN.search(line) and "valueFrom" not in line:
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="possible secret in environment configuration",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="host_path_volume",
                        severity="medium",
                        message="hostPath volume — verify path is minimal and read-only",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if AUTOMOUNT_TRUE_PATTERN.match(raw):
                findings.append(
                    KubernetesFinding(
                        kind="automount_sa_token",
                        severity="medium",
                        message="automountServiceAccountToken: true — disable if unused",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

        if DANGEROUS_HOST_PATH_PATTERN.search(content):
            findings.append(
                KubernetesFinding(
                    kind="dangerous_host_path",
                    severity="high",
                    message="hostPath mounts sensitive host directory",
                    path=rel,
                    lineno=0,
                    resource=current_resource,
                )
            )

        if CAP_ADD_ALL_CONTENT_PATTERN.search(content):
            findings.append(
                KubernetesFinding(
                    kind="cap_add_all",
                    severity="high",
                    message="capabilities add ALL grants all Linux capabilities",
                    path=rel,
                    lineno=0,
                    resource=current_resource,
                )
            )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesInfo] = []
        paths = self.manifests()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_resources = sum(len(i.resources) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = KubernetesStats(
            manifests=len(paths),
            findings=len(findings),
            resources=total_resources,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> KubernetesStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[KubernetesInfo]:
        """Return parsed manifest metadata."""
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
        """Scaffold a hardened Kubernetes Deployment template."""
        return """\
# Generated by DevAI KubernetesAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: ghcr.io/org/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              memory: "256Mi"
              cpu: "500m"
            requests:
              memory: "128Mi"
              cpu: "100m"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes manifests: none found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), "
            f"{stats.resources} resource(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low) — health {self.health_score():.0f}/100"
        )

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health_score: {self.health_score():.0f}/100",
            "",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        return "\n".join(lines)
