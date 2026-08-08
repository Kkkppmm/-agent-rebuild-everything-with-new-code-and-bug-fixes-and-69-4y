"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")
K8S_KIND_PATTERN = re.compile(r"^kind:\s*(\w+)", re.IGNORECASE)
K8S_API_VERSION_PATTERN = re.compile(r"^apiVersion:\s*", re.IGNORECASE)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:name:\s*)?(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"^\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(resources:\s*$|limits:\s*$|requests:\s*$|memory:\s*|cpu:\s*)",
    re.IGNORECASE,
)
SERVICE_ACCOUNT_AUTO_MOUNT_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken:\s*true\b",
    re.IGNORECASE,
)
HOST_PATH_TYPE_PATTERN = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)


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
    """Parsed metadata about a Kubernetes manifest file."""

    path: str
    resources: list[str] = field(default_factory=list)
    has_resource_limits: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifest_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_k8s_manifest(path: Path, content: str) -> bool:
    if any(part.lower() in K8S_DIR_NAMES for part in path.parts):
        return True
    if path.suffix.lower() in (".yaml", ".yml"):
        head = content[:2000]
        return bool(K8S_API_VERSION_PATTERN.search(head) and K8S_KIND_PATTERN.search(head))
    return False


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, host namespaces, root execution,
    secrets in environment variables, :latest image tags, missing resource
    limits, sensitive hostPath mounts, and excessive capabilities.
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
            if not path.is_file():
                continue
            if path.suffix.lower() not in (".yaml", ".yml"):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _looks_like_k8s_manifest(path, content):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        in_capabilities_add = False
        capabilities_indent = 0
        in_host_path = False
        host_path_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = K8S_KIND_PATTERN.match(line)
            if kind_match:
                current_resource = kind_match.group(1)
                if current_resource not in info.resources:
                    info.resources.append(current_resource)
                continue

            if line.startswith("metadata:") and "name:" in raw:
                continue

            if RESOURCE_LIMIT_PATTERN.search(line):
                info.has_resource_limits = True

            if HOST_PATH_TYPE_PATTERN.match(line):
                in_host_path = True
                host_path_indent = len(raw) - len(raw.lstrip())
                continue

            if in_host_path:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= host_path_indent and not line.startswith("path:"):
                    in_host_path = False
                elif HOST_PATH_SENSITIVE_PATTERN.match(line):
                    findings.append(
                        KubernetesFinding(
                            kind="sensitive_hostpath",
                            severity="high",
                            message="hostPath mounts sensitive host directory — container escape risk",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )
                    in_host_path = False

            if line.startswith("capabilities:"):
                in_capabilities_add = False
                continue

            if line.startswith("add:"):
                in_capabilities_add = True
                capabilities_indent = len(raw) - len(raw.lstrip())
                continue

            if in_capabilities_add:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= capabilities_indent and not line.startswith("-"):
                    in_capabilities_add = False
                elif CAP_ADD_ALL_PATTERN.match(line):
                    findings.append(
                        KubernetesFinding(
                            kind="cap_add_all",
                            severity="high",
                            message="container adds ALL capabilities — excessive privilege",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            checks: list[tuple[re.Pattern[str], str, str, str]] = [
                (PRIVILEGED_PATTERN, "privileged", "high", "container runs in privileged mode"),
                (HOST_NETWORK_PATTERN, "host_network", "high", "pod uses hostNetwork — shares host network stack"),
                (HOST_PID_PATTERN, "host_pid", "high", "pod uses hostPID — can observe host processes"),
                (HOST_IPC_PATTERN, "host_ipc", "medium", "pod uses hostIPC — shares host IPC namespace"),
                (RUN_AS_ROOT_PATTERN, "run_as_root", "high", "container configured to run as root"),
                (ALLOW_PRIV_ESC_PATTERN, "allow_privilege_escalation", "medium", "allowPrivilegeEscalation is true"),
                (LATEST_TAG_PATTERN, "latest_tag", "medium", "image uses :latest tag — pin to a specific version"),
                (PLAIN_SECRET_VALUE_PATTERN, "secret_in_manifest", "high", "potential secret hardcoded in manifest — use Secrets"),
                (SECRET_ENV_PATTERN, "secret_env_name", "medium", "env var name suggests secret — prefer secretKeyRef"),
                (SERVICE_ACCOUNT_AUTO_MOUNT_PATTERN, "automount_sa_token", "low", "automountServiceAccountToken is true — disable if unused"),
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
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

        if info.resources and not info.has_resource_limits:
            has_workload = any(
                r in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job")
                for r in info.resources
            )
            if has_workload:
                findings.append(
                    KubernetesFinding(
                        kind="missing_resource_limits",
                        severity="low",
                        message="workload manifest has no resource limits/requests — risk of noisy neighbor",
                        path=rel,
                        lineno=0,
                        resource=",".join(info.resources[:3]),
                        line="",
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

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = KubernetesStats(
            manifest_files=len(paths),
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
    def infos(self) -> list[KubernetesInfo]:
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
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
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
            f"Kubernetes: {stats.manifest_files} manifest(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifest files: {stats.manifest_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            resources = ", ".join(info.resources[:6]) or "none"
            lines.append(f"  - {info.path}: [{resources}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
