"""GardenAnalyzer — audit Garden.io configs for security and Kubernetes dev best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GARDEN_FILENAMES = (
    "garden.yml",
    "garden.yaml",
    "project.garden.yml",
    "project.garden.yaml",
)
GARDEN_DIRS = ("garden", "deploy/garden", "k8s/garden", "manifests/garden")
GARDEN_MARKER_PATTERN = re.compile(
    r"(?:^apiVersion\s*:\s*garden\.io/|^\s*kind\s*:\s*(?:Project|Module|Build|Deploy|Run|Test|Workflow)|"
    r"^\s*providers\s*:|^\s*environments\s*:|^\s*services\s*:|^\s*modules\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#{}\s][^\s#]*)",
    re.IGNORECASE,
)
HARDCODED_VAR_PATTERN = re.compile(
    r"^\s*(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#{}\s][^\s#]*)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repo|url|chart|registry|repository|base|helmRepo|oci|hostname)\s*:\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
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
    r"(?:insecureSkipTLSVerify|skipTLSVerify|insecure_skip_tls_verify|tls\s*:\s*false)",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|clusterRole\s*:\s*cluster-admin",
    re.IGNORECASE,
)
PROD_CONTEXT_PATTERN = re.compile(
    r"(?:context|defaultEnvironment|kubeContext|namespace|defaultNamespace)\s*:\s*"
    r"[\"']?(?:prod|production|live|staging)[\"']?",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser|runAsNonRoot)\s*:\s*(?:0|false)",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"hostPath\s*:\s*[\"']?/(?:etc|proc|sys|var/run/docker\.sock)",
    re.IGNORECASE,
)
SYNC_SENSITIVE_PATTERN = re.compile(
    r"(?:path|sourcePath|targetPath|sync)\s*:\s*[\"']?(?:\.env|\.git|/etc|/proc|/sys)",
    re.IGNORECASE,
)
INLINE_KUBECONFIG_PATTERN = re.compile(
    r"(?:kubeconfig|kubeConfig)\s*:\s*[\"']?[A-Za-z0-9+/=]{20,}",
    re.IGNORECASE,
)
BUILD_MODE_LOCAL_PATTERN = re.compile(
    r"buildMode\s*:\s*[\"']?(?:local-docker|cluster-build)[\"']?",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git::)?https?://[^\s\"']+(?![^\n]*(?:ref=|commit=|tag=|@))",
    re.IGNORECASE,
)


@dataclass
class GardenFinding:
    """A security or best-practice issue in a Garden configuration."""

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
class GardenInfo:
    """Parsed metadata about a Garden config file."""

    path: str
    kind: str = ""
    name: str = ""
    modules: int = 0
    services: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class GardenStats:
    """Aggregate Garden analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_garden_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in GARDEN_FILENAMES or lower.endswith(".garden.yml") or lower.endswith(".garden.yaml"):
        return True
    if lower.endswith((".yaml", ".yml")):
        parts = {p.lower() for p in path.parts}
        if parts & set(GARDEN_DIRS):
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if GARDEN_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class GardenAnalyzer:
    """Audit Garden.io configs for hardcoded secrets, insecure registries, and risky dev settings.

    Scans ``project.garden.yml`` and ``garden.yml`` for plaintext variables, insecure HTTP
    registries, :latest tags, docker.sock mounts, production kube contexts, inline kubeconfig,
    and sensitive sync paths.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GardenFinding] | None = None
        self._stats: GardenStats | None = None
        self._infos: list[GardenInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Garden configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_garden_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GardenFinding], GardenInfo]:
        findings: list[GardenFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GardenInfo(path=rel)

        raw_lines = text.splitlines()
        info = GardenInfo(path=rel, lines=len(raw_lines))

        in_variables = False
        services: list[str] = []
        module_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            kind_match = re.search(r"^\s*kind\s*:\s*(\w+)", line, re.IGNORECASE)
            if kind_match:
                info.kind = kind_match.group(1)

            name_match = re.search(r"^\s*name\s*:\s*[\"']?([^\"'\s#]+)", line, re.IGNORECASE)
            if name_match and not info.name:
                info.name = name_match.group(1)

            if re.search(r"^\s*variables\s*:\s*$", line, re.IGNORECASE):
                in_variables = True
            elif in_variables and not line.startswith(" ") and not line.startswith("-"):
                in_variables = False

            if re.search(r"^\s*-\s*name\s*:", line, re.IGNORECASE) and "modules" in text.lower():
                module_count += 1

            service_match = re.search(r"^\s*([a-zA-Z0-9_-]+)\s*:\s*$", line)
            if service_match and lineno > 1:
                prev = raw_lines[lineno - 2].strip().lower()
                if prev == "services:" or prev.endswith("services:"):
                    services.append(service_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line) or (
                in_variables and HARDCODED_VAR_PATTERN.search(line)
            ):
                findings.append(
                    GardenFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Garden config — use Garden secrets or external secret managers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Garden config — use IAM roles or secret references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    GardenFinding(
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
                    GardenFinding(
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
                    GardenFinding(
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
                    GardenFinding(
                        kind="skip_tls_verify",
                        severity="high",
                        message="TLS verification disabled — enable TLS verification for registries and clusters",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    GardenFinding(
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
                    GardenFinding(
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
                    GardenFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount exposes host Docker daemon — use remote builders or Kaniko",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in exec or lifecycle hook — use pinned artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin RBAC — restrict to namespace-scoped roles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_CONTEXT_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="production_target",
                        severity="medium",
                        message="context or namespace targets production-like environment — isolate dev from prod",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="root_container",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot and non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="host_path_mount",
                        severity="high",
                        message="hostPath mount to sensitive host directory — use PVCs or emptyDir",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SYNC_SENSITIVE_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="sync_sensitive_path",
                        severity="high",
                        message="sync/hot-reload includes sensitive path — exclude .env, .git, and system paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_KUBECONFIG_PATTERN.search(line):
                findings.append(
                    GardenFinding(
                        kind="inline_kubeconfig",
                        severity="high",
                        message="inline kubeconfig in Garden config — use context references or secret files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BUILD_MODE_LOCAL_PATTERN.search(line) and DOCKER_SOCKET_PATTERN.search(text):
                findings.append(
                    GardenFinding(
                        kind="local_docker_build",
                        severity="medium",
                        message="local-docker buildMode with docker.sock access — prefer cluster-build or remote builders",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git::" in line.lower() or "repositoryUrl" in line.lower()
            ):
                if "ref=" not in line and "commit=" not in line and "tag=" not in line:
                    findings.append(
                        GardenFinding(
                            kind="unpinned_git_source",
                            severity="medium",
                            message="git remote source without ref/commit pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        info.modules = module_count
        info.services = services
        return findings, info

    def analyze(self) -> list[GardenFinding]:
        """Scan Garden configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GardenFinding] = []
        infos: list[GardenInfo] = []
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
        self._stats = GardenStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GardenStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GardenInfo]:
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
        """Scaffold a hardened Garden project configuration."""
        return """\
apiVersion: garden.io/v2
kind: Project
name: app

environments:
  - name: dev
    defaultNamespace: app-dev
    variables:
      IMAGE_TAG: ${local.env.IMAGE_TAG || "dev"}

providers:
  - name: kubernetes
    environments: [dev]
    buildMode: cluster-build
    namespace: ${environment.namespace}
    defaultHostname: app-${environment.name}.local.demo.garden

---
kind: Build
name: api
type: container
source:
  path: ./api
spec:
  dockerfile: Dockerfile

---
kind: Deploy
name: api
type: container
dependencies: [build.api]
spec:
  image: ${actions.build.api.outputs.deploymentImageId}
  ports:
    - name: http
      containerPort: 8080
  sync:
    paths:
      - sourcePath: ./api/src
        targetPath: /app/src
        exclude:
          - .git
          - .env
          - node_modules
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Garden configs: none found"
        return (
            f"Garden configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Garden analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            service_list = ", ".join(info.services) if info.services else "none"
            lines.append(
                f"  - {info.path}: kind={info.kind or 'unknown'}, "
                f"{info.modules} module(s), services: {service_list}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
