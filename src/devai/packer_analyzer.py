"""PackerAnalyzer — audit HashiCorp Packer configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PACKER_FILENAMES = (
    "packer.hcl",
    "packer.json",
)
PACKER_SUFFIXES = (".pkr.hcl", ".pkr.json")
PACKER_BLOCK_PATTERN = re.compile(r"^\s*packer\s*\{", re.IGNORECASE)
SOURCE_BLOCK_PATTERN = re.compile(r'^\s*source\s+"[^"]+"\s+"[^"]+"\s*\{', re.IGNORECASE)
BUILD_BLOCK_PATTERN = re.compile(r"^\s*build\s*\{", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|"
    r"access[_-]?key|secret[_-]?key)\s*=\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
AWS_SECRET_KEY_PATTERN = re.compile(
    r"(?:secret[_-]?access[_-]?key|aws_secret_access_key)\s*=\s*[\"'][^\"']{20,}[\"']",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:ami|image|source|repository)\s*=\s*[\"'][^\"']+:latest[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:iso_url|url|source)\s*=\s*[\"']http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SSH_PASSWORD_PATTERN = re.compile(
    r"(?:ssh_password|ssh_passwd)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
WINRM_PASSWORD_PATTERN = re.compile(
    r"(?:winrm_password|winrm_passwd)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
ENCRYPT_BOOT_DISABLED_PATTERN = re.compile(
    r"encrypt_boot\s*=\s*false",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"privileged\s*=\s*true",
    re.IGNORECASE,
)
SKIP_CHECKSUM_PATTERN = re.compile(
    r"checksum\s*=\s*[\"']?[\"']?\s*$|skip_checksum\s*=\s*true",
    re.IGNORECASE,
)
PLAINTEXT_ENV_VAR_PATTERN = re.compile(
    r"(?:environment_vars|user_data)\s*=\s*\{[^}]*"
    r"(?:password|secret|token|api[_-]?key)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE | re.DOTALL,
)
FORCE_DEREGISTER_PATTERN = re.compile(
    r"force_deregister\s*=\s*true",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(
    r"(?:run_as|elevated_user)\s*=\s*[\"']?(?:Administrator|root)[\"']?",
    re.IGNORECASE,
)


@dataclass
class PackerFinding:
    """A security or best-practice issue in a Packer configuration file."""

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
class PackerInfo:
    """Parsed metadata about a Packer configuration file."""

    path: str
    has_build: bool = False
    has_source: bool = False
    builders: list[str] = field(default_factory=list)
    provisioners: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class PackerStats:
    """Aggregate Packer analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_packer_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in PACKER_FILENAMES:
        return True
    if any(lower.endswith(suffix) for suffix in PACKER_SUFFIXES):
        return True
    if path.suffix.lower() not in (".hcl", ".json"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        PACKER_BLOCK_PATTERN.search(text)
        or SOURCE_BLOCK_PATTERN.search(text)
        or BUILD_BLOCK_PATTERN.search(text)
        or re.search(
            r"\b(?:packer|source|build|provisioner)\s+[\"']",
            text,
            re.IGNORECASE,
        )
    )


class PackerAnalyzer:
    """Audit HashiCorp Packer configs for hardcoded secrets, :latest tags, and unsafe provisioners.

    Scans ``packer.hcl``, ``*.pkr.hcl``, and related HCL/JSON files for plaintext credentials,
    unencrypted EBS volumes, curl-pipe-to-shell provisioners, and insecure download URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PackerFinding] | None = None
        self._stats: PackerStats | None = None
        self._infos: list[PackerInfo] | None = None

    def files(self) -> list[Path]:
        """Return Packer configuration files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_packer_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PackerFinding], PackerInfo]:
        findings: list[PackerFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PackerInfo(path=rel)

        info = PackerInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            if PACKER_BLOCK_PATTERN.match(line):
                pass

            source_match = re.match(
                r'^\s*source\s+"([^"]+)"\s+"([^"]+)"\s*\{',
                line,
                re.IGNORECASE,
            )
            if source_match:
                info.has_source = True
                builder = source_match.group(1)
                if builder not in info.builders:
                    info.builders.append(builder)

            if BUILD_BLOCK_PATTERN.match(line):
                info.has_build = True

            prov_match = re.match(
                r'^\s*provisioner\s+"([^"]+)"\s*\{',
                line,
                re.IGNORECASE,
            )
            if prov_match:
                prov = prov_match.group(1)
                if prov not in info.provisioners:
                    info.provisioners.append(prov)

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use IAM roles, env vars, or Packer variables",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if AWS_SECRET_KEY_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="hardcoded_aws_secret",
                        severity="high",
                        message="hardcoded AWS secret key — use IAM roles, env vars, or Packer variables",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Packer config — use variables and sensitive flag",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SSH_PASSWORD_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="ssh_password",
                        severity="high",
                        message="plaintext ssh_password — use SSH keys or a secrets manager",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if WINRM_PASSWORD_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="winrm_password",
                        severity="high",
                        message="plaintext winrm_password — use WinRM over HTTPS with managed credentials",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="latest_tag",
                        severity="medium",
                        message=":latest image/AMI tag — pin to a specific version for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in provisioner — verify checksums and pin script versions",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP download URL — use HTTPS and verify checksums",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if ENCRYPT_BOOT_DISABLED_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="encrypt_boot_disabled",
                        severity="medium",
                        message="encrypt_boot = false — enable EBS encryption for AMI volumes",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker builder — avoid privileged containers in image builds",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SKIP_CHECKSUM_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="missing_checksum",
                        severity="medium",
                        message="missing or skipped checksum for downloaded artifact — pin checksums for supply-chain safety",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="run_as_root",
                        severity="low",
                        message="provisioner runs as root/Administrator — use least-privilege user where possible",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if FORCE_DEREGISTER_PATTERN.search(line):
                findings.append(
                    PackerFinding(
                        kind="force_deregister",
                        severity="low",
                        message="force_deregister = true — ensure AMIs are not unexpectedly removed in production pipelines",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if PLAINTEXT_ENV_VAR_PATTERN.search("\n".join(raw_lines)):
            findings.append(
                PackerFinding(
                    kind="plaintext_env_secret",
                    severity="high",
                    message="plaintext secret in environment_vars or user_data — use sensitive variables",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and info.has_source and not info.has_build:
            findings.append(
                PackerFinding(
                    kind="missing_build",
                    severity="low",
                    message="source blocks defined without a build block — verify pipeline wires sources to builds",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[PackerFinding]:
        """Scan Packer configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PackerFinding] = []
        infos: list[PackerInfo] = []
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
        self._stats = PackerStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PackerStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PackerInfo]:
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
        """Scaffold a hardened Packer HCL2 configuration template."""
        return """\
# Hardened Packer configuration template
packer {
  required_version = ">= 1.9.0"
  required_plugins {
    amazon = {
      version = "~> 1.3"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "source_ami" {
  type        = string
  description = "Pinned AMI ID — never use :latest"
}

variable "ssh_username" {
  type    = string
  default = "ec2-user"
}

source "amazon-ebs" "hardened" {
  region                  = var.aws_region
  source_ami              = var.source_ami
  instance_type           = "t3.small"
  ssh_username            = var.ssh_username
  encrypt_boot            = true
  ami_name                = "hardened-{{timestamp}}"
  force_deregister        = false
  force_delete_snapshot   = true
  temporary_key_pair_type   = "ed25519"
}

build {
  sources = ["source.amazon-ebs.hardened"]

  provisioner "shell" {
    inline = [
      "sudo dnf update -y",
      "sudo systemctl enable sshd",
    ]
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Packer: none found"
        return (
            f"Packer: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Packer config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: builders={info.builders or 'none'}, "
                f"provisioners={info.provisioners or 'none'}, build={info.has_build}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
