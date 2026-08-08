"""KubernetesAnalyzer — audit K8s manifests for privileged mode, host namespaces, and secrets in env."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_KIND_PATTERN = re.compile(
    r"^\s*kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|ReplicaSet)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(r"runAsNonRoot:\s*false\b", re.IGNORECASE)
ALLOW_PRIV_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s:]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
HOST_PATH_MOUNT_PATTERN = re.compile(r"path:\s*/\s*$", re.IGNORECASE)
MISSING_LIMITS_PATTERN = re.compile(r"resources:\s*$", re.IGNORECASE)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(r"readOnlyRootFilesystem:\s*false\b", re.IGNORECASE)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

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
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    containers: int = 0
    has_resource_limits: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(K8S_KIND_PATTERN.search(text))


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, host namespaces, secrets in env,
    :latest image tags, missing resource limits, and hostPath mounts to /.
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
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        env_indent = 0
        in_resources = False
        has_limits = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = K8S_KIND_PATTERN.match(line)
            if kind_match:
                info.kinds.append(kind_match.group(1))

            if line.startswith("- name:") or re.match(r"^\s*-?\s*name:\s*\S+", line):
                if "container" in raw.lower() or lineno > 1:
                    info.containers += 1

            if line == "env:" or line.endswith(" env:"):
                in_env_block = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent and not line.startswith("- "):
                    in_env_block = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        KubernetesFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret in env — use Kubernetes Secrets",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("resources:"):
                in_resources = True
                has_limits = False
                continue

            if in_resources and re.match(r"^\s*limits:", line):
                has_limits = True
                info.has_resource_limits = True

            if in_resources and line and not line.startswith(" ") and not line.startswith("\t"):
                if not has_limits and info.containers > 0:
                    findings.append(
                        KubernetesFinding(
                            kind="missing_resource_limits",
                            severity="medium",
                            message="container resources block without limits — set CPU/memory limits",
                            path=rel,
                            lineno=lineno - 1,
                            line="",
                        )
                    )
                in_resources = False

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access — avoid in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true exposes pod to host network stack",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares host process namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_NON_ROOT_FALSE_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsNonRoot: false allows container to run as root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESCALATION_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="privilege_escalation",
                        severity="high",
                        message="allowPrivilegeEscalation: true can escalate container privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_MOUNT_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_path_root",
                        severity="high",
                        message="hostPath mount to / exposes entire host filesystem",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if READ_ONLY_ROOT_FALSE_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="writable_root_fs",
                        severity="medium",
                        message="readOnlyRootFilesystem: false — prefer read-only root filesystem",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
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

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = KubernetesStats(
            manifests=len(paths),
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
  replicas: 2
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: myregistry/app:1.0.0
          ports:
            - containerPort: 8000
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
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), "
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
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            kinds = ", ".join(info.kinds) or "unknown"
            lines.append(
                f"  - {info.path}: kind=[{kinds}], {info.containers} container(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
