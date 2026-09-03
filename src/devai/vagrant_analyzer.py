"""VagrantAnalyzer — audit Vagrant configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

VAGRANT_FILENAMES = (
    "Vagrantfile",
    "vagrantfile",
)
VAGRANT_SUFFIXES = (".vagrant",)
VAGRANT_CONFIGURE_PATTERN = re.compile(r"Vagrant\.configure\s*\(", re.IGNORECASE)
BOX_PATTERN = re.compile(r'config\.vm\.box\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
BOX_VERSION_PATTERN = re.compile(r"config\.vm\.box_version\s*=", re.IGNORECASE)
SSH_PASSWORD_PATTERN = re.compile(
    r"config\.ssh\.password\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
SSH_INSERT_KEY_DISABLED_PATTERN = re.compile(
    r"config\.ssh\.insert_key\s*=\s*false",
    re.IGNORECASE,
)
SSH_FORWARD_AGENT_PATTERN = re.compile(
    r"config\.ssh\.forward_agent\s*=\s*true",
    re.IGNORECASE,
)
SSH_VERIFY_HOST_KEY_DISABLED_PATTERN = re.compile(
    r"(?:config\.ssh\.verify_host_key\s*=\s*:never|"
    r"StrictHostKeyChecking\s+no|UserKnownHostsFile\s+/dev/null)",
    re.IGNORECASE,
)
FORWARDED_PORT_ALL_INTERFACES_PATTERN = re.compile(
    r'config\.vm\.network\s+["\']forwarded_port["\'].*host_ip:\s*["\']0\.0\.0\.0["\']',
    re.IGNORECASE,
)
FORWARDED_PORT_NO_HOST_IP_PATTERN = re.compile(
    r'config\.vm\.network\s+["\']forwarded_port["\']',
    re.IGNORECASE,
)
HOST_IP_PATTERN = re.compile(r"host_ip:\s*[\"']", re.IGNORECASE)
INSECURE_HTTP_BOX_PATTERN = re.compile(
    r'config\.vm\.box_url\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)[^\s"\']+',
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"secret[_-]?key)\s*[=:]\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
NFS_SYNCED_FOLDER_PATTERN = re.compile(
    r'config\.vm\.synced_folder\s+[^,]+,\s*[^,]+,\s*type:\s*["\']nfs["\']',
    re.IGNORECASE,
)
RSYNC_CHOWN_DISABLED_PATTERN = re.compile(
    r"rsync__chown:\s*false",
    re.IGNORECASE,
)
PROVIDER_CREDENTIAL_PATTERN = re.compile(
    r"(?:aws\.access_key_id|aws\.secret_access_key|"
    r"azure\.client_id|azure\.client_secret|"
    r"google\.project_id|google\.credentials)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
PUBLIC_NETWORK_PATTERN = re.compile(
    r'config\.vm\.network\s+["\']public_network["\']',
    re.IGNORECASE,
)
INSECURE_KEY_PATH_PATTERN = re.compile(
    r"config\.ssh\.private_key_path\s*=\s*[\"'][^\"']*(?:id_rsa|\.pem|\.key)[\"']",
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
    box: str = ""
    has_box_version: bool = False
    providers: list[str] = field(default_factory=list)
    provisioners: list[str] = field(default_factory=list)
    forwarded_ports: int = 0
    synced_folders: int = 0
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
    if lower in (name.lower() for name in VAGRANT_FILENAMES):
        return True
    if any(lower.endswith(suffix) for suffix in VAGRANT_SUFFIXES):
        return True
    if path.suffix.lower() not in (".rb", ""):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        VAGRANT_CONFIGURE_PATTERN.search(text)
        or re.search(r"config\.vm\.", text, re.IGNORECASE)
    )


class VagrantAnalyzer:
    """Audit Vagrant configs for plaintext SSH passwords, unbound port forwards, and unsafe provisioners.

    Scans ``Vagrantfile`` and related Ruby configs for hardcoded credentials, missing box version pins,
    ``forward_agent``, disabled host key verification, curl-pipe-to-shell provisioners, and NFS/rsync
    misconfigurations.
    """

    def __init__(self, root: str = ".") -> None:
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
        text = "\n".join(raw_lines)

        box_match = BOX_PATTERN.search(text)
        if box_match:
            info.box = box_match.group(1)
        info.has_box_version = bool(BOX_VERSION_PATTERN.search(text))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()

            if re.search(r'config\.vm\.provider\s+["\']([^"\']+)["\']', stripped, re.IGNORECASE):
                provider_match = re.search(
                    r'config\.vm\.provider\s+["\']([^"\']+)["\']',
                    stripped,
                    re.IGNORECASE,
                )
                if provider_match:
                    provider = provider_match.group(1)
                    if provider not in info.providers:
                        info.providers.append(provider)

            if re.search(r'config\.vm\.provision\s+["\']([^"\']+)["\']', stripped, re.IGNORECASE):
                prov_match = re.search(
                    r'config\.vm\.provision\s+["\']([^"\']+)["\']',
                    stripped,
                    re.IGNORECASE,
                )
                if prov_match:
                    prov = prov_match.group(1)
                    if prov not in info.provisioners:
                        info.provisioners.append(prov)

            if FORWARDED_PORT_NO_HOST_IP_PATTERN.search(stripped):
                info.forwarded_ports += 1

            if re.search(r"config\.vm\.synced_folder", stripped, re.IGNORECASE):
                info.synced_folders += 1

            if SSH_PASSWORD_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="ssh_password",
                        severity="high",
                        message="plaintext SSH password — use SSH keys and config.ssh.insert_key",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use env vars or provider credential chain",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PROVIDER_CREDENTIAL_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="provider_credential",
                        severity="high",
                        message="hardcoded cloud provider credential — use env vars or ~/.vagrant.d/boxes",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(stripped) and not SSH_PASSWORD_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Vagrantfile — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SSH_INSERT_KEY_DISABLED_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="insert_key_disabled",
                        severity="medium",
                        message="config.ssh.insert_key = false — insecure default SSH key handling",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SSH_FORWARD_AGENT_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="forward_agent",
                        severity="medium",
                        message="SSH agent forwarding enabled — can expose local keys to the guest",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SSH_VERIFY_HOST_KEY_DISABLED_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="host_key_verification_disabled",
                        severity="high",
                        message="SSH host key verification disabled — vulnerable to MITM attacks",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if FORWARDED_PORT_ALL_INTERFACES_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="port_forward_all_interfaces",
                        severity="high",
                        message="port forward bound to 0.0.0.0 — exposes guest ports on all interfaces",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if (
                FORWARDED_PORT_NO_HOST_IP_PATTERN.search(stripped)
                and not HOST_IP_PATTERN.search(stripped)
            ):
                findings.append(
                    VagrantFinding(
                        kind="port_forward_no_host_ip",
                        severity="medium",
                        message="forwarded port without host_ip — defaults to all interfaces; bind to 127.0.0.1",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_BOX_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="insecure_http_box",
                        severity="medium",
                        message="box downloaded over HTTP — use HTTPS box URLs",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in provisioner — verify script integrity first",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if NFS_SYNCED_FOLDER_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="nfs_synced_folder",
                        severity="low",
                        message="NFS synced folder — ensure exports restrict client access",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if RSYNC_CHOWN_DISABLED_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="rsync_chown_disabled",
                        severity="low",
                        message="rsync__chown disabled — may leave incorrect file ownership in guest",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PUBLIC_NETWORK_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="public_network",
                        severity="medium",
                        message="public_network exposes VM on LAN — ensure firewall rules are in place",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_KEY_PATH_PATTERN.search(stripped):
                findings.append(
                    VagrantFinding(
                        kind="hardcoded_key_path",
                        severity="low",
                        message="hardcoded private key path — prefer Vagrant's key management",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if info.box and not info.has_box_version:
            findings.append(
                VagrantFinding(
                    kind="unpinned_box",
                    severity="medium",
                    message=f"box '{info.box}' has no box_version pin — builds may be non-reproducible",
                    path=rel,
                    lineno=1,
                    line=f'config.vm.box = "{info.box}"',
                )
            )

        if not VAGRANT_CONFIGURE_PATTERN.search(text):
            findings.append(
                VagrantFinding(
                    kind="missing_configure",
                    severity="low",
                    message="no Vagrant.configure block found — file may be incomplete",
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
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = "20231215.0.0"

  config.ssh.insert_key = true
  config.ssh.forward_agent = false

  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  config.vm.synced_folder ".", "/vagrant",
    owner: "vagrant",
    group: "vagrant",
    mount_options: ["dmode=755", "fmode=644"]

  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    sudo apt-get update -y
    sudo apt-get upgrade -y
  SHELL

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
    vb.gui = false
  end
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
                f"  - {info.path}: box={info.box or 'none'}, "
                f"providers={info.providers or 'none'}, "
                f"provisioners={info.provisioners or 'none'}, "
                f"ports={info.forwarded_ports}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
