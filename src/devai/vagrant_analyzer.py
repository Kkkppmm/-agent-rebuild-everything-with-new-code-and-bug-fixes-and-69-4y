"""VagrantAnalyzer — audit HashiCorp Vagrant configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

VAGRANT_FILENAMES = ("Vagrantfile", "vagrantfile")
VAGRANT_CONFIGURE_PATTERN = re.compile(r"Vagrant\.configure\s*\(", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|"
    r"access[_-]?key|secret[_-]?key)\s*[=:]\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
SSH_PASSWORD_PATTERN = re.compile(
    r"config\.ssh\.password\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
PRIVATE_KEY_INLINE_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
INSECURE_KEY_PATTERN = re.compile(
    r"(?:config\.ssh\.insert_key|insert_key)\s*=\s*false",
    re.IGNORECASE,
)
FORWARD_AGENT_PATTERN = re.compile(
    r"config\.ssh\.forward_agent\s*=\s*true",
    re.IGNORECASE,
)
PUBLIC_NETWORK_PATTERN = re.compile(
    r'config\.vm\.network\s+["\']public_network["\']',
    re.IGNORECASE,
)
FORWARD_ALL_INTERFACES_PATTERN = re.compile(
    r"(?:guest_ip|host_ip)\s*[:=]\s*[\"']0\.0\.0\.0[\"']",
    re.IGNORECASE,
)
INSECURE_HTTP_BOX_PATTERN = re.compile(
    r"(?:config\.vm\.box_url|box_url)\s*=\s*[\"']http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SHELL_PROVISIONER_PATTERN = re.compile(
    r'config\.vm\.provision\s+["\']shell["\']',
    re.IGNORECASE,
)
DISABLE_SYNCED_FOLDER_PATTERN = re.compile(
    r"config\.vm\.synced_folder\s+[\"']\.[\"']\s*,\s*[\"']/vagrant[\"']\s*,\s*disabled:\s*true",
    re.IGNORECASE,
)
NFS_INSECURE_PATTERN = re.compile(
    r"(?:nfs_version|nfs_udp)\s*[:=]\s*(?:3|true)|nfs:\s*\{[^}]*insecure:\s*true",
    re.IGNORECASE,
)
LATEST_BOX_PATTERN = re.compile(
    r'config\.vm\.box\s*=\s*["\'][^"\']+:latest["\']',
    re.IGNORECASE,
)
GUI_ENABLED_PATTERN = re.compile(
    r"(?:config\.vm\.provider|vb)\.(?:gui|name)\s*=\s*true",
    re.IGNORECASE,
)
RDP_ENABLED_PATTERN = re.compile(
    r"(?:rdp\.enabled|config\.vm\.communicator)\s*=\s*true",
    re.IGNORECASE,
)
AWS_PROVIDER_SECRET_PATTERN = re.compile(
    r"(?:aws\.access_key_id|aws\.secret_access_key)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
DOCKER_PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged|privileged_mode)\s*=\s*true",
    re.IGNORECASE,
)
AUTO_UPDATE_PLUGIN_PATTERN = re.compile(
    r"config\.vagrant\.plugins\.auto_update\s*=\s*true",
    re.IGNORECASE,
)


@dataclass
class VagrantFinding:
    """A security or best-practice issue in a Vagrant configuration file."""

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
class VagrantInfo:
    """Parsed metadata about a Vagrant configuration file."""

    path: str
    providers: list[str] = field(default_factory=list)
    provisioners: list[str] = field(default_factory=list)
    box: str = ""
    has_network: bool = False
    lines: int = 0


@dataclass
class VagrantStats:
    """Aggregate Vagrant analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vagrant_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in VAGRANT_FILENAMES:
        return True
    if path.suffix.lower() not in (".rb", ""):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(VAGRANT_CONFIGURE_PATTERN.search(text))


class VagrantAnalyzer:
    """Audit HashiCorp Vagrant configs for hardcoded secrets, insecure networking, and unsafe provisioners.

    Scans ``Vagrantfile`` and related Ruby configs for plaintext SSH passwords, AWS keys,
    public network exposure, SSH agent forwarding, curl-pipe-to-shell provisioners, and insecure box URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VagrantFinding] | None = None
        self._stats: VagrantStats | None = None
        self._infos: list[VagrantInfo] | None = None

    def files(self) -> list[Path]:
        """Return Vagrant configuration files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_vagrant_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[VagrantFinding], VagrantInfo]:
        findings: list[VagrantFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, VagrantInfo(path=rel)

        info = VagrantInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            box_match = re.search(
                r'config\.vm\.box\s*=\s*["\']([^"\']+)["\']',
                line,
                re.IGNORECASE,
            )
            if box_match:
                info.box = box_match.group(1)

            provider_match = re.search(
                r'config\.vm\.provider\s+["\']([^"\']+)["\']',
                line,
                re.IGNORECASE,
            )
            if provider_match:
                provider = provider_match.group(1)
                if provider not in info.providers:
                    info.providers.append(provider)

            prov_match = re.search(
                r'config\.vm\.provision\s+["\']([^"\']+)["\']',
                line,
                re.IGNORECASE,
            )
            if prov_match:
                prov = prov_match.group(1)
                if prov not in info.provisioners:
                    info.provisioners.append(prov)

            if re.search(r"config\.vm\.network", line, re.IGNORECASE):
                info.has_network = True

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use environment variables or ~/.aws/credentials",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if AWS_PROVIDER_SECRET_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_aws_secret",
                        severity="high",
                        message="hardcoded AWS provider credentials — use env vars or IAM instance profiles",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Vagrantfile — use environment variables or vault plugins",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SSH_PASSWORD_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="ssh_password",
                        severity="high",
                        message="plaintext config.ssh.password — use SSH keys instead of passwords",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PRIVATE_KEY_INLINE_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="inline_private_key",
                        severity="high",
                        message="inline private key in Vagrantfile — store keys outside version control",
                        path=rel,
                        lineno=lineno,
                        line=stripped[:80],
                    )
                )

            if INSECURE_KEY_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="insecure_ssh_key",
                        severity="medium",
                        message="config.ssh.insert_key = false — Vagrant may reuse insecure default keys",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if FORWARD_AGENT_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="ssh_forward_agent",
                        severity="medium",
                        message="SSH agent forwarding enabled — guest compromise can access forwarded keys",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PUBLIC_NETWORK_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="public_network",
                        severity="medium",
                        message="public_network exposes VM on LAN — restrict with firewall rules",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if FORWARD_ALL_INTERFACES_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="bind_all_interfaces",
                        severity="medium",
                        message="port forwarding bound to 0.0.0.0 — bind to 127.0.0.1 for local-only access",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_BOX_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="insecure_box_url",
                        severity="medium",
                        message="cleartext HTTP box URL — use HTTPS and verify checksums",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LATEST_BOX_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="latest_box_tag",
                        severity="low",
                        message="box tagged :latest — pin to a specific box version for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in provisioner — verify checksums and pin script versions",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if DOCKER_PRIVILEGED_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker provider — avoid privileged containers in dev VMs",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if NFS_INSECURE_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="insecure_nfs",
                        severity="medium",
                        message="insecure NFS synced folder options — use NFSv4 and avoid insecure exports",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if GUI_ENABLED_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="gui_enabled",
                        severity="low",
                        message="GUI mode enabled — disable for headless CI and server environments",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if AUTO_UPDATE_PLUGIN_PATTERN.search(line):
                findings.append(
                    VagrantFinding(
                        kind="auto_update_plugins",
                        severity="low",
                        message="auto_update plugins enabled — pin plugin versions for reproducible environments",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if raw_lines and not info.box and info.providers:
            findings.append(
                VagrantFinding(
                    kind="missing_box",
                    severity="low",
                    message="provider configured without config.vm.box — verify box source is defined",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[VagrantFinding]:
        """Scan Vagrant configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VagrantFinding] = []
        infos: list[VagrantInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = VagrantStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VagrantStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VagrantInfo]:
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Vagrantfile template."""
        return """\
# Hardened Vagrantfile template
# frozen_string_literal: true

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = "20240126.0.0"
  config.vm.box_check_update = false

  config.ssh.insert_key = true
  config.ssh.forward_agent = false

  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 1024
    vb.cpus = 2
    vb.gui = false
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    sudo apt-get update -y
    sudo apt-get upgrade -y
  SHELL
end
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Vagrant: none found"
        return (
            f"Vagrant: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Vagrant config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: box={info.box or 'unset'}, "
                f"providers={info.providers or 'none'}, "
                f"provisioners={info.provisioners or 'none'}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
