"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = ("k8s", "kubernetes", "deploy", "deployment", "manifests", "helm")
K8S_KIND_PATTERN = re.compile(
    r"^\s*kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|CronJob|Job|Service)",
    re.IGNORECASE,
)

LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b|runAsNonRoot:\s*false\b", re.IGNORECASE)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
SECRET_ENV_NAME_PATTERN = re.compile(
    r"name:\s*[^\n]*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)",
    re.IGNORECASE,
)
SECRET_ENV_LITERAL_PATTERN = re.compile(
    r"value:\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
MISSING_LIMITS_CONTEXT = re.compile(
    r"containers:\s*$|^\s*-\s*name:",
    re.IGNORECASE,
)
RESOURCE_LIMITS_PATTERN = re.compile(
    r"(limits|requests):\s*$|memory:\s*|cpu:\s*",
    re.IGNORECASE,
)


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
class K8sInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    containers: int = 0
    lines: int = 0


@dataclass
class K8sStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    parts = path.parts
    for part in parts:
        if part.lower() in K8S_DIR_NAMES:
            return True
    if path.name.lower().endswith(("-deployment.yaml", "-deployment.yml")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
        if K8S_KIND_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class K8sAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, hostNetwork, root runAsUser, sensitive
    hostPath mounts, secrets in env literals, :latest image tags, and missing
    resource limits.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[K8sFinding], K8sInfo]:
        findings: list[K8sFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, K8sInfo(path=rel)

        info = K8sInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        in_containers = False
        container_indent = 0
        container_has_limits = False
        container_name = ""
        pending_secret_env = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            kind_match = re.match(r"^kind:\s*(\S+)", line, re.IGNORECASE)
            if kind_match:
                current_resource = kind_match.group(1)
                info.kinds.append(current_resource)

            name_match = re.match(r"^name:\s*(\S+)", line, re.IGNORECASE)
            if name_match and indent <= 4:
                current_resource = name_match.group(1)

            if line == "containers:" or line.startswith("containers:"):
                in_containers = True
                container_indent = indent
                continue

            if in_containers and indent <= container_indent and not line.startswith("-"):
                in_containers = False

            if in_containers and line.startswith("- name:"):
                name_value = line.split("name:", 1)[-1].strip()
                if indent == container_indent + 2 and name_value:
                    if not container_has_limits and container_name:
                        findings.append(
                            K8sFinding(
                                kind="missing_resource_limits",
                                severity="medium",
                                message="container missing resource limits/requests — set memory and CPU bounds",
                                path=rel,
                                lineno=lineno,
                                resource=container_name,
                                line=raw.strip(),
                            )
                        )
                    container_has_limits = False
                    container_name = name_value
                    info.containers += 1
                elif SECRET_ENV_NAME_PATTERN.search(line):
                    pending_secret_env = True

            if RESOURCE_LIMITS_PATTERN.search(line):
                container_has_limits = True

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_image",
                        severity="medium",
                        message="container image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true exposes pod to host network stack",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="container runs as root — set runAsNonRoot: true and runAsUser > 0",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_SENSITIVE_PATTERN.search(line) and (
                "hostpath" in raw.lower() or "path:" in line.lower()
            ):
                findings.append(
                    K8sFinding(
                        kind="sensitive_hostpath",
                        severity="high",
                        message="hostPath mount to sensitive host path — avoid mounting /, /etc, or docker.sock",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if pending_secret_env and SECRET_ENV_LITERAL_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="secret_env_literal",
                        severity="high",
                        message="secret hardcoded in env — use Kubernetes Secrets and secretKeyRef",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )
                pending_secret_env = False

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sInfo] = []
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
        self._stats = K8sStats(
            manifests=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> K8sStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[K8sInfo]:
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
# Generated by DevAI K8sAnalyzer
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
      containers:
        - name: app
          image: myapp:1.0.0
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "500m"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: none found"
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
            kinds = ", ".join(info.kinds[:5]) or "none"
            lines.append(
                f"  - {info.path}: {info.containers} container(s), kinds=[{kinds}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
