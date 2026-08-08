"""KubernetesAnalyzer — audit Kubernetes manifests for security and best-practice issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm", "charts")
K8S_SUFFIXES = (".yaml", ".yml")
K8S_KINDS = (
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE = re.compile(r"runAsNonRoot:\s*false\b", re.IGNORECASE)
PRIV_ESC_PATTERN = re.compile(r"allowPrivilegeEscalation:\s*true\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"\b(password|secret|api[_-]?key|token|credential)\s*:\s*['\"]?[^\s'\"${}]+",
    re.IGNORECASE,
)
ENV_SECRET_NAME_PATTERN = re.compile(
    r"name:\s*['\"]?(?:\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|CREDENTIAL)\w*)['\"]?\s*$",
    re.IGNORECASE,
)
CAP_ALL_PATTERN = re.compile(r"-\s*ALL\b", re.IGNORECASE)
CAP_SYS_ADMIN_PATTERN = re.compile(r"-\s*SYS_ADMIN\b", re.IGNORECASE)
HOST_PATH_SENSITIVE = re.compile(
    r"path:\s*['\"]?(?:/etc|/proc|/sys|/var/run|/root|/dev)['\"]?",
    re.IGNORECASE,
)
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
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class KubernetesResourceInfo:
    """Parsed metadata about a Kubernetes resource."""

    name: str
    kind: str = ""
    privileged: bool = False
    host_network: bool = False


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifest_files: int
    resources: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


def _is_kubernetes_manifest(path: Path) -> bool:
    name = path.name.lower()
    if not any(name.endswith(suffix) for suffix in K8S_SUFFIXES):
        return False
    if any(part.lower() in K8S_DIR_NAMES for part in path.parts):
        return True
    if name.startswith(("deployment", "service", "ingress", "configmap", "secret", "statefulset")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return bool(API_VERSION_PATTERN.search(head, re.MULTILINE))


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for pod security and deployment risks.

    Detects privileged containers, host namespaces, root execution,
    :latest image tags, docker.sock mounts, hardcoded secrets, and
  dangerous capabilities.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._resources: list[KubernetesResourceInfo] | None = None

    def manifest_files(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_kubernetes_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], list[KubernetesResourceInfo]]:
        findings: list[KubernetesFinding] = []
        resources: list[KubernetesResourceInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, resources

        current_kind = ""
        current_name = ""
        resource_map: dict[str, KubernetesResourceInfo] = {}
        in_cap_add = False
        doc_has_api_version = False
        pending_secret_env = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line.strip():
                continue

            if API_VERSION_PATTERN.match(line.strip()):
                doc_has_api_version = True

            kind_match = re.match(r"^kind:\s*(\S+)", line.strip(), re.IGNORECASE)
            if kind_match:
                current_kind = kind_match.group(1)
                current_name = ""

            name_match = re.match(r"^\s{2}name:\s*(\S+)", line)
            if name_match and current_kind:
                current_name = name_match.group(1).strip("'\"")
                key = f"{current_kind}/{current_name}"
                if key not in resource_map:
                    info = KubernetesResourceInfo(name=current_name, kind=current_kind)
                    resource_map[key] = info
                    resources.append(info)

            info = resource_map.get(f"{current_kind}/{current_name}") if current_name else None
            resource_label = f"{current_kind}/{current_name}" if current_name else current_kind
            stripped = line.strip()

            if re.match(r"^\s*capabilities:\s*$", line, re.IGNORECASE):
                in_cap_add = False
            if re.match(r"^\s*add:\s*$", line, re.IGNORECASE):
                in_cap_add = True
            elif in_cap_add and CAP_ALL_PATTERN.search(stripped):
                findings.append(
                    KubernetesFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL grants excessive Linux capabilities",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )
                in_cap_add = False
            elif in_cap_add and CAP_SYS_ADMIN_PATTERN.search(stripped):
                findings.append(
                    KubernetesFinding(
                        kind="cap_sys_admin",
                        severity="high",
                        message="SYS_ADMIN capability enables broad host-level control",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )
                in_cap_add = False
            elif stripped and not stripped.startswith("-") and "add:" not in stripped.lower():
                in_cap_add = False

            checks = [
                (LATEST_TAG_PATTERN, "latest_tag", "medium", "container image uses :latest — pin a specific version"),
                (PRIVILEGED_PATTERN, "privileged", "high", "privileged: true grants full host access to the container"),
                (HOST_NETWORK_PATTERN, "host_network", "high", "hostNetwork bypasses pod network isolation"),
                (HOST_PID_PATTERN, "host_pid", "high", "hostPID shares host process namespace"),
                (HOST_IPC_PATTERN, "host_ipc", "high", "hostIPC shares host IPC namespace"),
                (RUN_AS_ROOT_PATTERN, "runs_as_root", "medium", "runAsUser: 0 runs the container as root"),
                (RUN_AS_NON_ROOT_FALSE, "runs_as_root", "medium", "runAsNonRoot: false allows root execution"),
                (PRIV_ESC_PATTERN, "privilege_escalation", "medium", "allowPrivilegeEscalation: true can escalate privileges"),
                (DOCKER_SOCK_PATTERN, "docker_sock_mount", "high", "mounting /var/run/docker.sock enables host container escape"),
                (HOST_PATH_SENSITIVE, "sensitive_hostpath", "high", "hostPath mount to a sensitive host directory"),
            ]

            for pattern, kind, severity, message in checks:
                if pattern.search(line):
                    findings.append(
                        KubernetesFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            resource=resource_label,
                            line=raw.strip(),
                        )
                    )
                    if info:
                        if kind == "privileged":
                            info.privileged = True
                        if kind == "host_network":
                            info.host_network = True

            if SECRET_ENV_PATTERN.search(line) and "${" not in line and "valueFrom:" not in line:
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret in manifest — use Kubernetes Secrets",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if ENV_SECRET_NAME_PATTERN.search(line):
                pending_secret_env = True
            elif pending_secret_env and re.search(r"^\s*value:\s*['\"]?[^\s'\"${}]+", line):
                if "valueFrom:" not in line:
                    findings.append(
                        KubernetesFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="hardcoded secret in env value — use secretKeyRef",
                            path=rel,
                            lineno=lineno,
                            resource=resource_label,
                            line=raw.strip(),
                        )
                    )
                pending_secret_env = False
            elif pending_secret_env and stripped.startswith("- "):
                pending_secret_env = False

        if not doc_has_api_version and resources:
            pass

        return findings, resources

    def analyze(self) -> list[KubernetesFinding]:
        """Scan manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        resources: list[KubernetesResourceInfo] = []
        paths = self.manifest_files()

        for path in paths:
            file_findings, file_resources = self._analyze_file(path)
            findings.extend(file_findings)
            resources.extend(file_resources)

        self._findings = findings
        self._resources = resources
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = KubernetesStats(
            manifest_files=len(paths),
            resources=len(resources),
            findings=len(findings),
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
    def resources(self) -> list[KubernetesResourceInfo]:
        """Return parsed resource metadata."""
        if self._resources is None:
            self.analyze()
        return self._resources  # type: ignore[return-value]

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
              cpu: 500m
              memory: 512Mi
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: database-url
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
            return "Kubernetes manifests: none found"
        return (
            f"Kubernetes manifests: {stats.manifest_files} file(s), "
            f"{stats.resources} resource(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes analysis:",
            f"  manifest files: {stats.manifest_files}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for res in self.resources[:15]:
            flags = []
            if res.privileged:
                flags.append("privileged")
            if res.host_network:
                flags.append("host-network")
            flag_text = f" [{', '.join(flags)}]" if flags else ""
            kind = res.kind or "Resource"
            lines.append(f"  - {kind}/{res.name}{flag_text}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
