"""K8sAnalyzer — audit Kubernetes manifests for security and deployment best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIRS = ("k8s", "kubernetes", "deploy", "manifests", "charts")
K8S_SUFFIXES = (".yaml", ".yml")

LATEST_IMAGE_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
SECRET_ENV_NAME_PATTERN = re.compile(
    r"name:\s*(PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL|DB_PASSWORD)",
    re.IGNORECASE,
)
SECRET_ENV_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
NO_RUN_AS_NON_ROOT_PATTERN = re.compile(r"runAsNonRoot:\s*false\b", re.IGNORECASE)
ALLOW_PRIVILEGE_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
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
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class K8sManifestInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
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
    if path.suffix.lower() not in K8S_SUFFIXES:
        return False
    parts = path.parts
    if any(d in parts for d in K8S_DIRS):
        return True
    # Also match files with k8s-related names at any level
    name_lower = path.name.lower()
    return any(
        token in name_lower
        for token in ("deployment", "service", "ingress", "configmap", "secret", "pod", "statefulset")
    )


class K8sAnalyzer:
    """Audit Kubernetes manifests for privileged containers, :latest images, and insecure settings."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sManifestInfo] | None = None

    def manifests(self) -> list[Path]:
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
        in_security_context = False
        in_env = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                if kind not in info.kinds:
                    info.kinds.append(kind)

            if "securityContext:" in line:
                in_security_context = True
            if line.endswith(":") and not line.startswith("-") and "securityContext" not in line:
                key = line[:-1].strip()
                if key not in ("env", "containers", "spec", "template", "metadata"):
                    in_security_context = False
                if key == "env":
                    in_env = True
                    env_indent = len(raw) - len(raw.lstrip())
                elif key != "env":
                    in_env = False

            if "image:" in line.lower() and LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_image",
                        severity="medium",
                        message="container image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
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
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true allows container to see host processes",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_context and RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 runs container as root — use a non-root UID",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_context and NO_RUN_AS_NON_ROOT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_non_root_false",
                        severity="medium",
                        message="runAsNonRoot: false allows root execution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIVILEGE_ESCALATION_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privilege_escalation",
                        severity="high",
                        message="allowPrivilegeEscalation: true can escalate container privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env and SECRET_ENV_VALUE_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
                    findings.append(
                        K8sFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret in env — use Kubernetes Secrets",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if in_env and SECRET_ENV_NAME_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="sensitive env var name — use Kubernetes Secrets instead of literal values",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sManifestInfo] = []
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
    def infos(self) -> list[K8sManifestInfo]:
        """Return parsed manifest metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0 or stats.findings == 0:
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
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
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
            kinds = ", ".join(info.kinds) or "unknown"
            lines.append(f"  - {info.path}: kinds=[{kinds}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
