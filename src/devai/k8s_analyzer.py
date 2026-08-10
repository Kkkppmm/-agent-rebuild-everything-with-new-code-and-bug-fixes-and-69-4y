"""K8sManifestAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Pod",
    "CronJob",
    "Job",
    "ReplicaSet",
)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_USER_ZERO_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
DOCKER_SOCK_HOSTPATH_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
HOST_ROOT_HOSTPATH_PATTERN = re.compile(
    r"^\s*path:\s*['\"]?/(?:etc|proc|sys|var/lib/kubelet)['\"]?\s*$",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
LOAD_BALANCER_PATTERN = re.compile(
    r"^\s*type:\s*LoadBalancer\b",
    re.IGNORECASE,
)
NODE_PORT_PATTERN = re.compile(r"^\s*type:\s*NodePort\b", re.IGNORECASE)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(limits:\s*$|memory:\s*['\"]?\d|cpu:\s*['\"]?\d|resources:\s*$)",
    re.IGNORECASE,
)
RUN_AS_NON_ROOT_PATTERN = re.compile(r"^\s*runAsNonRoot:\s*true\b", re.IGNORECASE)
READ_ONLY_ROOT_PATTERN = re.compile(
    r"^\s*readOnlyRootFilesystem:\s*true\b",
    re.IGNORECASE,
)
ENV_VALUE_PATTERN = re.compile(r"^\s*value:\s+", re.IGNORECASE)
SECRET_KEY_REF_PATTERN = re.compile(r"secretKeyRef|valueFrom:", re.IGNORECASE)


@dataclass
class K8sFinding:
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
class K8sManifestInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class K8sManifestStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifest_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    lower = head.lower()
    return "apiversion:" in lower and "kind:" in lower


class K8sManifestAnalyzer:
    """Audit Kubernetes YAML manifests for security risks and cluster best practices.

    Scans for privileged pods, host namespaces, dangerous hostPath mounts, secrets in
  env literals, :latest image tags, missing resource limits, and overly permissive
    service exposure.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sManifestStats | None = None
        self._infos: list[K8sManifestInfo] | None = None

    def manifest_files(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[K8sFinding], K8sManifestInfo]:
        findings: list[K8sFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, K8sManifestInfo(path=rel)

        info = K8sManifestInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        current_kind = ""
        in_containers = False
        container_indent = 0
        container_has_limits = False
        container_has_run_as_non_root = False
        container_has_read_only_root = False
        in_env = False
        env_indent = 0
        env_entry_has_secret_ref = False
        in_capabilities_add = False
        cap_indent = 0
        in_hostpath = False
        hostpath_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            kind_match = re.match(r"^kind:\s*(\S+)", line, re.IGNORECASE)
            if kind_match:
                current_kind = kind_match.group(1)
                if current_kind in K8S_KINDS:
                    info.kinds.append(current_kind)

            name_match = re.match(r"^metadata:\s*$", line, re.IGNORECASE)
            if name_match:
                current_resource = ""

            meta_name_match = re.match(r"^name:\s*(\S+)", line, re.IGNORECASE)
            if meta_name_match and indent <= 4:
                current_resource = meta_name_match.group(1)
                if current_resource not in info.resources:
                    info.resources.append(current_resource)

            if line == "containers:" or line.startswith("containers:"):
                in_containers = True
                continue

            if in_containers and line.endswith(":") and indent <= container_indent + 2:
                if current_resource and not container_has_limits and current_kind in K8S_KINDS:
                    findings.append(
                        K8sFinding(
                            kind="no_resource_limits",
                            severity="low",
                            message=(
                                "container has no resource limits — "
                                "set resources.limits for cpu and memory"
                            ),
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                        )
                    )
                if (
                    current_resource
                    and not container_has_run_as_non_root
                    and current_kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job")
                ):
                    findings.append(
                        K8sFinding(
                            kind="no_run_as_non_root",
                            severity="medium",
                            message=(
                                "container securityContext missing runAsNonRoot: true — "
                                "may run as root"
                            ),
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                        )
                    )
                if current_resource and not container_has_read_only_root:
                    findings.append(
                        K8sFinding(
                            kind="no_read_only_root",
                            severity="low",
                            message=(
                                "readOnlyRootFilesystem not enabled — "
                                "consider hardening the container filesystem"
                            ),
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                        )
                    )
                if line.strip().endswith(":") and not line.startswith("-"):
                    key = line[:-1].strip()
                    if key and key[0].isalpha():
                        container_indent = indent
                        container_has_limits = False
                        container_has_run_as_non_root = False
                        container_has_read_only_root = False
                        in_env = False
                        in_capabilities_add = False
                        in_hostpath = False

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the pod",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true bypasses pod network isolation",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares the host PID namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_ipc",
                        severity="high",
                        message="hostIPC: true shares the host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_USER_ZERO_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 runs the container as root",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_NON_ROOT_FALSE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_non_root_false",
                        severity="high",
                        message="runAsNonRoot: false explicitly allows root execution",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true weakens container isolation",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if LOAD_BALANCER_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="load_balancer",
                        severity="medium",
                        message=(
                            "Service type LoadBalancer exposes the workload publicly — "
                            "restrict with network policies and ingress controls"
                        ),
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if NODE_PORT_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="node_port",
                        severity="low",
                        message=(
                            "Service type NodePort binds a port on every node — "
                            "prefer ClusterIP with ingress"
                        ),
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if line == "hostPath:" or line.startswith("hostPath:"):
                in_hostpath = True
                hostpath_indent = indent
                continue

            if in_hostpath:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= hostpath_indent and line.endswith(":"):
                    in_hostpath = False
                elif DOCKER_SOCK_HOSTPATH_PATTERN.search(line):
                    findings.append(
                        K8sFinding(
                            kind="docker_sock_hostpath",
                            severity="high",
                            message=(
                                "hostPath mounts /var/run/docker.sock — "
                                "grants host Docker API access"
                            ),
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )
                elif HOST_ROOT_HOSTPATH_PATTERN.match(line):
                    findings.append(
                        K8sFinding(
                            kind="dangerous_hostpath",
                            severity="high",
                            message="hostPath mounts sensitive host paths",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            if line == "capabilities:" or line.startswith("capabilities:"):
                in_capabilities_add = False
                continue

            if line == "add:" or (line.startswith("add:") and "capabilities" in raw.lower()):
                in_capabilities_add = True
                cap_indent = indent
                continue

            if in_capabilities_add and CAP_ADD_ALL_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL grants every Linux capability",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if in_capabilities_add:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= cap_indent and line.endswith(":"):
                    in_capabilities_add = False

            if line == "env:" or line.startswith("env:"):
                in_env = True
                env_indent = indent
                env_entry_has_secret_ref = False
                continue

            if in_env:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= env_indent and line.endswith(":") and not line.startswith("-"):
                    in_env = False
                elif SECRET_KEY_REF_PATTERN.search(line):
                    env_entry_has_secret_ref = True
                elif ENV_VALUE_PATTERN.match(line) and SECRET_VALUE_PATTERN.search(line):
                    if not env_entry_has_secret_ref:
                        findings.append(
                            K8sFinding(
                                kind="secret_in_env",
                                severity="high",
                                message=(
                                    "potential secret in env value — "
                                    "use secretKeyRef or external secrets operator"
                                ),
                                path=rel,
                                lineno=lineno,
                                resource=current_resource,
                                line=raw.strip(),
                            )
                        )
                    env_entry_has_secret_ref = False
                elif line.startswith("- name:"):
                    env_entry_has_secret_ref = False

            if RESOURCE_LIMIT_PATTERN.search(line):
                container_has_limits = True

            if RUN_AS_NON_ROOT_PATTERN.match(line):
                container_has_run_as_non_root = True

            if READ_ONLY_ROOT_PATTERN.match(line):
                container_has_read_only_root = True

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sManifestInfo] = []
        paths = self.manifest_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = K8sManifestStats(
            manifest_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> K8sManifestStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[K8sManifestInfo]:
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
# Generated by DevAI K8sManifestAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    app: app
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
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: python:3.12-slim
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
              cpu: "1"
              memory: 512Mi
          ports:
            - name: http
              containerPort: 8000
          env:
            - name: APP_ENV
              value: production
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
            return "Kubernetes manifests: none found"
        lines = [
            (
                f"Kubernetes manifests: {stats.manifest_files} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "# Kubernetes Manifest Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                kinds = ", ".join(info.kinds) if info.kinds else "unknown"
                resources = ", ".join(info.resources) if info.resources else "none"
                lines.append(f"- {info.path}: kinds [{kinds}], resources [{resources}]")
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
