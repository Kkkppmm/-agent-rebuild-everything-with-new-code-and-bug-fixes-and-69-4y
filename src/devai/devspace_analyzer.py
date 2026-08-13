"""DevSpaceAnalyzer — audit DevSpace configs for security and Kubernetes dev best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DEVSPACE_FILENAMES = (
    "devspace.yaml",
    "devspace.yml",
)
DEVSPACE_DIRS = ("devspace", "deploy/devspace", "k8s/devspace", "manifests/devspace")
DEVSPACE_MARKER_PATTERN = re.compile(
    r"(?:^version\s*:\s*v\d|^\s*devspace\s*:|deployments\s*:|pipelines\s*:|"
    r"dev\s*:\s*$|images\s*:\s*$)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_VAR_PATTERN = re.compile(
    r"^\s*(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repo|url|chart|registry|repository|base|helmRepo|oci)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|tag|value)\s*:\s*[\"']?[^\"'\s]*:latest[\"']?\s*$|"
    r"(?:tag|newTag)\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
INSECURE_REGISTRY_PATTERN = re.compile(
    r"(?:insecureRegistries|allowInsecure|insecure)\s*:\s*true",
    re.IGNORECASE,
)
SKIP_TLS_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|skipTLSVerify|insecure_skip_tls_verify)\s*:\s*true",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*:\s*true",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"hostNetwork\s*:\s*true",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
KUBECTL_FORCE_PATTERN = re.compile(
    r"(?:--force|--grace-period=0|--wait=false|replacePods\s*:\s*true)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|useClusterAdmin\s*:\s*true",
    re.IGNORECASE,
)
STATUS_CHECK_DISABLED_PATTERN = re.compile(
    r"(?:statusCheck|wait)\s*:\s*false",
    re.IGNORECASE,
)
SYNC_SENSITIVE_PATTERN = re.compile(
    r"(?:path|sync)\s*:\s*[\"']?(?:\.env|\.git|/etc|/proc|/sys)",
    re.IGNORECASE,
)
PORT_FORWARD_ALL_PATTERN = re.compile(
    r"(?:localPort|port)\s*:\s*[\"']?0[\"']?\s*$",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git::)?https?://[^\s\"']+(?![^\n]*(?:ref=|commit=|tag=|@))",
    re.IGNORECASE,
)
PROD_CONTEXT_PATTERN = re.compile(
    r"(?:kubeContext|namespace)\s*:\s*[\"']?(?:prod|production|live|staging)[\"']?",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser|runAsNonRoot)\s*:\s*(?:0|false)",
    re.IGNORECASE,
)
SSH_ENABLED_PATTERN = re.compile(
    r"^\s*ssh\s*:\s*$|^\s*enabled\s*:\s*true",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"hostPath\s*:\s*[\"']?/(?:etc|proc|sys|var/run/docker\.sock)",
    re.IGNORECASE,
)
PLAINTEXT_SECRET_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class DevSpaceFinding:
    """A security or best-practice issue in a DevSpace configuration."""

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
class DevSpaceInfo:
    """Parsed metadata about a DevSpace config file."""

    path: str
    version: str = ""
    images: int = 0
    deployments: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class DevSpaceStats:
    """Aggregate DevSpace analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_devspace_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in DEVSPACE_FILENAMES:
        return True
    if lower.endswith((".yaml", ".yml")):
        parts = {p.lower() for p in path.parts}
        if parts & set(DEVSPACE_DIRS):
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if DEVSPACE_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class DevSpaceAnalyzer:
    """Audit DevSpace configs for hardcoded secrets, insecure registries, and risky dev settings.

    Scans ``devspace.yaml`` for plaintext vars/secrets, insecure HTTP registries, :latest tags,
    docker.sock mounts, production kubeContext/namespace, enabled SSH into pods, force deploy,
    and sensitive path sync.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DevSpaceFinding] | None = None
        self._stats: DevSpaceStats | None = None
        self._infos: list[DevSpaceInfo] | None = None

    def configs(self) -> list[Path]:
        """Return DevSpace configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_devspace_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[DevSpaceFinding], DevSpaceInfo]:
        findings: list[DevSpaceFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DevSpaceInfo(path=rel)

        raw_lines = text.splitlines()
        info = DevSpaceInfo(path=rel, lines=len(raw_lines))

        in_vars = False
        in_secrets = False
        in_ssh = False
        deployments: list[str] = []
        image_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^version\s*:\s*v", line, re.IGNORECASE):
                match = re.search(r"version\s*:\s*(v[\w.]+)", line, re.IGNORECASE)
                if match:
                    info.version = match.group(1)

            if re.search(r"^\s*vars\s*:\s*$", line, re.IGNORECASE):
                in_vars = True
            elif in_vars and not line.startswith(" ") and not line.startswith("-"):
                in_vars = False

            if re.search(r"^\s*secrets\s*:\s*$", line, re.IGNORECASE):
                in_secrets = True
            elif in_secrets and not line.startswith(" ") and not line.startswith("-"):
                in_secrets = False

            if re.search(r"^\s*ssh\s*:\s*$", line, re.IGNORECASE):
                in_ssh = True
            elif in_ssh and not line.startswith(" "):
                in_ssh = False

            if re.search(r"^\s*-\s*image\s*:", line, re.IGNORECASE) or re.search(
                r"^\s*image\s*:\s*[^#\n]+", line, re.IGNORECASE
            ):
                image_count += 1

            deploy_match = re.search(r"^\s*([a-zA-Z0-9_-]+)\s*:\s*$", line)
            if deploy_match and lineno > 1:
                prev = raw_lines[lineno - 2].strip().lower()
                if prev == "deployments:" or prev.endswith("deployments:"):
                    deployments.append(deploy_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line) or (
                in_vars and HARDCODED_VAR_PATTERN.search(line)
            ):
                findings.append(
                    DevSpaceFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in DevSpace config — use secret files or external secret managers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_secrets and PLAINTEXT_SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="plaintext_secret_value",
                        severity="high",
                        message="plaintext secret value in DevSpace secrets — use from/file or external references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in DevSpace config — use IAM roles or secret references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="insecure HTTP registry or chart repo — use HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_REGISTRY_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="insecure_registry",
                        severity="high",
                        message="insecure registry setting enabled — use TLS-enabled registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TLS_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="skip_tls_verify",
                        severity="high",
                        message="TLS verification disabled for registry or cluster — enable TLS verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container enabled — avoid privileged mode in dev workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork enabled — isolate pod networking",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount exposes host Docker daemon — use remote builders or Kaniko",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if KUBECTL_FORCE_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="force_deploy",
                        severity="high",
                        message="force deploy or replacePods without graceful rollout — use standard apply with wait",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in pipeline or hook — use pinned artifacts or checksums",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin or useClusterAdmin — restrict RBAC to namespace-scoped roles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if STATUS_CHECK_DISABLED_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="status_check_disabled",
                        severity="medium",
                        message="status check or wait disabled — enable deployment readiness checks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SYNC_SENSITIVE_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="sync_sensitive_path",
                        severity="high",
                        message="dev sync includes sensitive path — exclude .env, .git, and system paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PORT_FORWARD_ALL_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="unsafe_port_forward",
                        severity="medium",
                        message="port forward uses port 0 — bind to explicit local ports",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_CONTEXT_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="production_target",
                        severity="medium",
                        message="kubeContext or namespace targets production-like environment — isolate dev from prod",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="root_container",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot and non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_ssh and re.search(r"enabled\s*:\s*true", line, re.IGNORECASE):
                findings.append(
                    DevSpaceFinding(
                        kind="ssh_into_pod",
                        severity="high",
                        message="SSH into dev pod enabled — prefer dev terminal or port-forward with auth",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.search(line):
                findings.append(
                    DevSpaceFinding(
                        kind="host_path_mount",
                        severity="high",
                        message="hostPath mount to sensitive host directory — use PVCs or emptyDir",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git::" in line.lower() or "git clone" in line.lower()
            ):
                if "ref=" not in line and "commit=" not in line and "tag=" not in line:
                    findings.append(
                        DevSpaceFinding(
                            kind="unpinned_git_source",
                            severity="medium",
                            message="git remote source without ref/commit pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        info.images = image_count
        info.deployments = deployments
        return findings, info

    def analyze(self) -> list[DevSpaceFinding]:
        """Scan DevSpace configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DevSpaceFinding] = []
        infos: list[DevSpaceInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = DevSpaceStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DevSpaceStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DevSpaceInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened DevSpace configuration."""
        return """\
version: v2beta1
name: app

vars:
  IMAGE: ghcr.io/org/app

images:
  app:
    image: ${IMAGE}
    dockerfile: Dockerfile
    tags:
      - ${DEVSPACE_RANDOM}

deployments:
  app:
    helm:
      chart:
        name: ./chart
      valuesFiles:
        - values.yaml
    updateImageTags: true

dev:
  ports:
    - port: "8080"
  sync:
    - path: ./src
      excludePaths:
        - .git
        - .env
        - node_modules
  terminal:
    enabled: true
  logs:
    enabled: true

pipelines:
  deploy:
    run: |-
      devspace deploy --wait
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "DevSpace configs: none found"
        return (
            f"DevSpace configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "DevSpace analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deployers = ", ".join(info.deployments) if info.deployments else "none"
            lines.append(
                f"  - {info.path}: {info.images} image(s), deployments: {deployers}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
