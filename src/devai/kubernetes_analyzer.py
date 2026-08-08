"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

K8S_DIRS = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "charts", "helm")
K8S_KINDS = (
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"^\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run)['\"]?\s*$",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(resources:\s*$|limits:\s*$|requests:\s*$|memory:\s*|cpu:\s*)",
    re.IGNORECASE,
)
KIND_PATTERN = re.compile(r"^\s*kind:\s*(\w+)\s*$", re.IGNORECASE)
NAME_PATTERN = re.compile(r"^\s*name:\s*(\S+)\s*$", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(
    r"^\s*(?:stringData|data):\s*$",
    re.IGNORECASE,
)
AUTOMOUNT_TRUE_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken:\s*true\b",
    re.IGNORECASE,
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
        resource = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{resource} — {self.message}"


@dataclass
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes analysis statistics."""

    manifests: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_kubernetes_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix not in (".yml", ".yaml"):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(K8S_DIRS):
        return True
    name = path.name.lower()
    if any(token in name for token in ("deployment", "service", "ingress", "configmap", "secret", "statefulset")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return "apiVersion:" in head and "kind:" in head


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root containers, secrets in env,
    :latest image tags, sensitive hostPath mounts, missing resource limits, and
    overly broad capabilities.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
        max_depth: int = 8,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self.max_depth = max_depth
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._infos: list[KubernetesInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        root_depth = len(self.root.parts)
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(self.root).parts
            if len(rel_parts) > self.max_depth:
                continue
            if any(part in self.ignore_dirs for part in rel_parts):
                continue
            if _is_kubernetes_file(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[KubernetesFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        path: Path,
        lineno: int,
        line: str,
        resource: str = "",
    ) -> None:
        findings.append(
            KubernetesFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path),
                lineno=lineno,
                line=line.strip(),
                resource=resource,
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        current_kind = ""
        current_name = ""
        in_security_context = False
        in_capabilities = False
        in_resources = False
        in_env = False
        env_indent = 0
        has_resource_limits = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = KIND_PATTERN.match(raw)
            if kind_match:
                current_kind = kind_match.group(1)
                if current_kind in K8S_KINDS:
                    info.kinds.append(current_kind)
                current_name = ""
                in_security_context = False
                in_capabilities = False
                in_resources = False
                in_env = False
                has_resource_limits = False
                continue

            name_match = NAME_PATTERN.match(raw)
            if name_match and current_kind and not current_name:
                current_name = name_match.group(1)
                resource_label = f"{current_kind}/{current_name}" if current_kind else current_name
                info.resources.append(resource_label)
                continue

            if line.startswith("securityContext:"):
                in_security_context = True
                in_capabilities = False
                in_env = False
                continue

            if line.startswith("capabilities:"):
                in_capabilities = True
                continue

            if line.startswith("resources:"):
                in_resources = True
                has_resource_limits = True
                continue

            if line.startswith("env:") or line.startswith("envFrom:"):
                in_env = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env and raw and not raw[0].isspace():
                in_env = False

            resource = f"{current_kind}/{current_name}" if current_kind and current_name else current_kind

            if PRIVILEGED_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="privileged",
                    severity="high",
                    message="privileged: true — avoid running containers with full host privileges",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if HOST_NETWORK_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="host_network",
                    severity="high",
                    message="hostNetwork: true — container shares the host network namespace",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if HOST_PID_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="host_pid",
                    severity="high",
                    message="hostPID: true — container can see host processes",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if HOST_IPC_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="host_ipc",
                    severity="medium",
                    message="hostIPC: true — container shares host IPC namespace",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if RUN_AS_ROOT_PATTERN.search(raw) or RUN_AS_NON_ROOT_FALSE_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="run_as_root",
                    severity="high",
                    message="Container may run as root — set runAsNonRoot: true and a non-zero runAsUser",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if ALLOW_PRIV_ESC_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="privilege_escalation",
                    severity="medium",
                    message="allowPrivilegeEscalation: true — restrict privilege escalation",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if LATEST_TAG_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="latest_tag",
                    severity="medium",
                    message="Image uses :latest tag — pin to a specific digest or version",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if DOCKER_SOCK_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="docker_socket",
                    severity="high",
                    message="Docker socket mount — grants container control over the host Docker daemon",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if HOST_PATH_SENSITIVE_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="sensitive_hostpath",
                    severity="high",
                    message="hostPath to sensitive host directory — avoid mounting /, /etc, /proc, or /sys",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if in_capabilities and CAP_ADD_ALL_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="cap_add_all",
                    severity="high",
                    message="capabilities add ALL — drop unnecessary capabilities instead",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if in_env and SECRET_ENV_PATTERN.search(raw):
                self._add_finding(
                    findings,
                    kind="secret_in_env",
                    severity="high",
                    message="Possible secret in env block — use Kubernetes Secrets and secretKeyRef",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if AUTOMOUNT_TRUE_PATTERN.search(raw) and current_kind in (
                "Deployment",
                "Pod",
                "StatefulSet",
                "DaemonSet",
            ):
                self._add_finding(
                    findings,
                    kind="automount_sa_token",
                    severity="low",
                    message="automountServiceAccountToken: true — disable if the pod does not need API access",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if current_kind == "Secret" and SECRET_VALUE_PATTERN.match(raw):
                self._add_finding(
                    findings,
                    kind="inline_secret_data",
                    severity="medium",
                    message="Inline secret data in manifest — prefer external secret management",
                    path=path,
                    lineno=lineno,
                    line=raw,
                    resource=resource,
                )

            if line and not line.startswith("-") and not raw.startswith(" " * 2):
                if in_security_context and not line.startswith("securityContext"):
                    in_security_context = False
                if in_capabilities and not line.startswith("capabilities"):
                    in_capabilities = False
                if in_resources and not line.startswith("resources"):
                    in_resources = False

        workload_kinds = {"Deployment", "Pod", "StatefulSet", "DaemonSet", "Job", "CronJob"}
        if current_kind in workload_kinds and not has_resource_limits and info.resources:
            self._add_finding(
                findings,
                kind="missing_resource_limits",
                severity="low",
                message="No resource limits/requests — set CPU and memory limits for stability",
                path=path,
                lineno=len(raw_lines),
                line="",
                resource=f"{current_kind}/{current_name}" if current_name else current_kind,
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

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        total_resources = sum(len(i.resources) for i in infos)

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
  labels:
    app: app
spec:
  replicas: 1
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
          image: ghcr.io/example/app:1.0.0
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          ports:
            - containerPort: 8080
              name: http
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), {stats.resources} resource(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            kinds = ", ".join(info.kinds[:6]) or "unknown"
            lines.append(f"  - {info.path}: {len(info.resources)} resource(s) [{kinds}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
