"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

K8S_DIR_NAMES = {"k8s", "kubernetes", "manifests", "deploy", "deployment", "helm", "charts"}
K8S_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Pod",
    "Job",
    "CronJob",
    "ReplicaSet",
}

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*readOnlyRootFilesystem:\s*false\b",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)
DANGEROUS_HOST_PATH_PATTERN = re.compile(
    r"path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"^\s*value:\s*['\"]?[^\s'\"]{4,}['\"]?\s*$",
    re.IGNORECASE,
)
SECRET_NAME_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
CAP_ALL_ADD_PATTERN = re.compile(r"^\s*add:\s*$", re.IGNORECASE)
CAP_ALL_DROP_PATTERN = re.compile(r"^\s*drop:\s*$", re.IGNORECASE)
CAP_ALL_ITEM_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
CAP_SYS_ADMIN_PATTERN = re.compile(r"^\s*-\s*SYS_ADMIN\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
AUTOMOUNT_TRUE_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken:\s*true\b",
    re.IGNORECASE,
)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"^\s*(limits|requests):\s*$",
    re.IGNORECASE,
)
KIND_PATTERN = re.compile(r"^kind:\s*(\S+)", re.IGNORECASE)
NAME_PATTERN = re.compile(r"^name:\s*(\S+)", re.IGNORECASE)
CONTAINER_NAME_PATTERN = re.compile(r"^\s*-\s*name:\s*(\S+)", re.IGNORECASE)
API_VERSION_PATTERN = re.compile(r"^apiVersion:\s*\S+", re.IGNORECASE)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    resource: str = ""
    container: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        parts = []
        if self.resource:
            parts.append(self.resource)
        if self.container:
            parts.append(self.container)
        ctx = f" ({', '.join(parts)})" if parts else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{ctx} — {self.message}"


@dataclass
class KubernetesResourceInfo:
    """Parsed metadata about a Kubernetes resource."""

    kind: str
    name: str
    containers: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesManifestInfo:
    """Parsed metadata about a Kubernetes manifest file."""

    path: str
    resources: list[KubernetesResourceInfo] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifest_files: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_kubernetes_manifest(path: Path) -> bool:
    name = path.name.lower()
    if not (name.endswith((".yaml", ".yml"))):
        return False
    if any(part.lower() in K8S_DIR_NAMES for part in path.parts):
        return True
    if any(token in name for token in ("deployment", "statefulset", "daemonset", "ingress", "service")):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(API_VERSION_PATTERN.search(text) and KIND_PATTERN.search(text))


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, host namespaces, :latest image tags,
    secrets in plain env, dangerous hostPath mounts, missing resource limits,
    and other common misconfigurations.
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
        self._infos: list[KubernetesManifestInfo] | None = None

    def manifest_files(self) -> list[Path]:
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
            if _is_kubernetes_manifest(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[KubernetesFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        path: str,
        lineno: int,
        resource: str = "",
        container: str = "",
        line: str = "",
    ) -> None:
        findings.append(
            KubernetesFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=path,
                lineno=lineno,
                resource=resource,
                container=container,
                line=line.strip(),
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesManifestInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesManifestInfo(path=rel)

        info = KubernetesManifestInfo(path=rel, lines=len(raw_lines))
        current_kind = ""
        current_name = ""
        current_resource: KubernetesResourceInfo | None = None
        in_containers = False
        containers_indent = 0
        current_container = ""
        container_indent = 0
        container_has_resources = False
        container_has_security_context = False
        container_run_as_non_root = False
        in_cap_add = False
        in_cap_drop = False
        cap_indent = 0
        last_env_name = ""

        def resource_label() -> str:
            if current_kind and current_name:
                return f"{current_kind}/{current_name}"
            if current_kind:
                return current_kind
            return ""

        def flush_container_checks(lineno: int) -> None:
            nonlocal container_has_resources, container_has_security_context, container_run_as_non_root
            nonlocal in_cap_add, in_cap_drop, last_env_name
            if not current_container:
                return
            if not container_has_security_context:
                self._add_finding(
                    findings,
                    kind="no_security_context",
                    severity="medium",
                    message="container has no securityContext — set runAsNonRoot and drop capabilities",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    container=current_container,
                )
            elif not container_run_as_non_root:
                self._add_finding(
                    findings,
                    kind="no_run_as_non_root",
                    severity="medium",
                    message="container may run as root — set securityContext.runAsNonRoot: true",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    container=current_container,
                )
            if not container_has_resources:
                self._add_finding(
                    findings,
                    kind="no_resource_limits",
                    severity="low",
                    message="no resource limits/requests — set resources.limits and resources.requests",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    container=current_container,
                )
            container_has_resources = False
            container_has_security_context = False
            container_run_as_non_root = False
            in_cap_add = False
            in_cap_drop = False
            last_env_name = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            kind_match = KIND_PATTERN.match(line)
            if kind_match:
                if current_resource:
                    info.resources.append(current_resource)
                current_kind = kind_match.group(1)
                current_name = ""
                current_resource = KubernetesResourceInfo(kind=current_kind, name="")
                in_containers = False
                current_container = ""
                continue

            name_match = NAME_PATTERN.match(line)
            if name_match and current_resource and not current_resource.name and indent <= 4:
                current_name = name_match.group(1)
                current_resource.name = current_name
                continue

            if line == "containers:" or line.startswith("containers:"):
                in_containers = True
                containers_indent = indent
                continue

            if in_containers and indent <= containers_indent and not line.startswith("- "):
                if line.endswith(":") and line not in ("containers:",):
                    flush_container_checks(lineno)
                    in_containers = False
                    current_container = ""

            container_match = CONTAINER_NAME_PATTERN.match(line)
            if in_containers and container_match and indent == containers_indent + 2:
                flush_container_checks(lineno)
                current_container = container_match.group(1)
                container_indent = indent
                if current_resource:
                    current_resource.containers.append(current_container)
                continue

            in_container_block = (
                in_containers
                and current_container
                and indent > container_indent
            )

            if in_container_block:
                if RESOURCE_LIMIT_PATTERN.match(line):
                    container_has_resources = True

                if line.startswith("securityContext:") or "securityContext:" in line:
                    container_has_security_context = True

                if re.search(r"runAsNonRoot:\s*true\b", line, re.IGNORECASE):
                    container_run_as_non_root = True

                if line.startswith("env:") or line == "env:":
                    last_env_name = ""

                env_name_match = re.match(r"^\s*-\s*name:\s*(\S+)", line)
                if env_name_match:
                    last_env_name = env_name_match.group(1)

                if SECRET_VALUE_PATTERN.match(line) and last_env_name:
                    if SECRET_NAME_PATTERN.search(last_env_name) or len(line.split(":", 1)[1].strip().strip("'\"")) >= 12:
                        self._add_finding(
                            findings,
                            kind="secret_in_env",
                            severity="high",
                            message="possible secret in plain env — use Secrets or external secret managers",
                            path=rel,
                            lineno=lineno,
                            resource=resource_label(),
                            container=current_container,
                            line=raw,
                        )

                if line.startswith("capabilities:") or line == "capabilities:":
                    cap_indent = indent
                    in_cap_add = False
                    in_cap_drop = False

                if indent > cap_indent and CAP_ALL_ADD_PATTERN.match(line):
                    in_cap_add = True
                    in_cap_drop = False
                elif indent > cap_indent and CAP_ALL_DROP_PATTERN.match(line):
                    in_cap_drop = True
                    in_cap_add = False

                if in_cap_add and CAP_ALL_ITEM_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL — drop unnecessary capabilities instead",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if PRIVILEGED_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if ALLOW_PRIV_ESC_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="allow_privilege_escalation",
                        severity="high",
                        message="allowPrivilegeEscalation: true — set to false for hardened workloads",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if RUN_AS_ROOT_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 runs container as root",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if RUN_AS_NON_ROOT_FALSE_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="run_as_non_root_false",
                        severity="high",
                        message="runAsNonRoot: false explicitly allows root execution",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if READ_ONLY_ROOT_FALSE_PATTERN.match(line):
                    self._add_finding(
                        findings,
                        kind="writable_root_fs",
                        severity="medium",
                        message="readOnlyRootFilesystem: false — prefer read-only root filesystem",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

                if LATEST_TAG_PATTERN.search(line):
                    self._add_finding(
                        findings,
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label(),
                        container=current_container,
                        line=raw,
                    )

            if HOST_NETWORK_PATTERN.match(line):
                self._add_finding(
                    findings,
                    kind="host_network",
                    severity="high",
                    message="hostNetwork: true bypasses pod network isolation",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

            if HOST_PID_PATTERN.match(line):
                self._add_finding(
                    findings,
                    kind="host_pid",
                    severity="high",
                    message="hostPID: true shares host process namespace",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

            if HOST_IPC_PATTERN.match(line):
                self._add_finding(
                    findings,
                    kind="host_ipc",
                    severity="high",
                    message="hostIPC: true shares host IPC namespace",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

            if HOST_PATH_PATTERN.match(line):
                self._add_finding(
                    findings,
                    kind="host_path_volume",
                    severity="medium",
                    message="hostPath volume — prefer PVCs or ConfigMaps where possible",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

            if DANGEROUS_HOST_PATH_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="dangerous_host_path",
                    severity="high",
                    message="dangerous hostPath mount — avoid mounting host root or docker.sock",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

            if CAP_SYS_ADMIN_PATTERN.match(line) and in_cap_add:
                self._add_finding(
                    findings,
                    kind="cap_sys_admin",
                    severity="high",
                    message="SYS_ADMIN capability is highly privileged",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    container=current_container,
                    line=raw,
                )

            if AUTOMOUNT_TRUE_PATTERN.match(line):
                self._add_finding(
                    findings,
                    kind="automount_sa_token",
                    severity="low",
                    message="automountServiceAccountToken: true — disable if service account unused",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label(),
                    line=raw,
                )

        flush_container_checks(len(raw_lines))

        if current_resource:
            info.resources.append(current_resource)

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesManifestInfo] = []
        paths = self.manifest_files()

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
            manifest_files=len(paths),
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
    def infos(self) -> list[KubernetesManifestInfo]:
        """Return parsed manifest metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
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
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: ghcr.io/org/app:1.0.0
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
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
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifest_files} manifest(s), {stats.resources} resource(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifest_files}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            for resource in info.resources[:5]:
                containers = ", ".join(resource.containers[:5]) or "none"
                lines.append(
                    f"  - {info.path}: {resource.kind}/{resource.name} "
                    f"[{containers}]"
                )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
