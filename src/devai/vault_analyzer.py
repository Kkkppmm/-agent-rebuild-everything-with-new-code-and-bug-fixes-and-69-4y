"""VaultAnalyzer — audit HashiCorp Vault configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

VAULT_FILENAMES = (
    "vault.hcl",
    "config.hcl",
    "vault-config.hcl",
    "vault.json",
)
VAULT_DIRS = ("vault", "config", "deploy", "infra", "terraform", "")

TLS_DISABLE_PATTERN = re.compile(r"^\s*tls_disable\s*=\s*true\s*$", re.IGNORECASE)
DISABLE_MLOCK_PATTERN = re.compile(r"^\s*disable_mlock\s*=\s*true\s*$", re.IGNORECASE)
RAW_STORAGE_PATTERN = re.compile(r"^\s*raw_storage_endpoint\s*=\s*true\s*$", re.IGNORECASE)
UI_ENABLED_PATTERN = re.compile(r"^\s*ui\s*=\s*true\s*$", re.IGNORECASE)
DEV_MODE_PATTERN = re.compile(r"^\s*dev\s*\{", re.IGNORECASE)
DEV_ROOT_TOKEN_PATTERN = re.compile(
    r"^\s*dev_root_token_id\s*=\s*[\"'][^\"']+[\"']\s*$",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|root_token|unseal_key)\s*=\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:hvs\.|s\.[A-Za-z0-9]{20,}|root|s\.[A-Za-z0-9_-]{20,})[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:api_addr|cluster_addr|address|redirect_addr|oidc_discovery_url)\s*=\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LISTENER_BLOCK_PATTERN = re.compile(r'^\s*listener\s+"tcp"\s*\{', re.IGNORECASE)
TLS_CERT_PATTERN = re.compile(r"^\s*tls_(?:cert|key)_file\s*=", re.IGNORECASE)
LONG_LEASE_PATTERN = re.compile(
    r"^\s*(?:default_lease_ttl|max_lease_ttl)\s*=\s*\"(\d+)h\"",
    re.IGNORECASE,
)
PLUGIN_DIR_PATTERN = re.compile(r"^\s*plugin_directory\s*=\s*", re.IGNORECASE)
AUDIT_DISABLED_PATTERN = re.compile(
    r"^\s*audit_device\s+\"[^\"]+\"\s*\{[^}]*file\s*\{[^}]*log_raw\s*=\s*true",
    re.IGNORECASE | re.DOTALL,
)
STORAGE_FILE_PATTERN = re.compile(r'^\s*storage\s+"file"\s*\{', re.IGNORECASE)
STORAGE_RAFT_PATTERN = re.compile(r'^\s*storage\s+"raft"\s*\{', re.IGNORECASE)
SEAL_BLOCK_PATTERN = re.compile(r'^\s*seal\s+"[^"]+"\s*\{', re.IGNORECASE)
TELEMETRY_DISABLED_PATTERN = re.compile(
    r"^\s*telemetry\s*\{[^}]*unauthenticated_metrics_access\s*=\s*true",
    re.IGNORECASE | re.DOTALL,
)
VAULT_BLOCK_PATTERN = re.compile(r'^\s*vault\s*\{', re.IGNORECASE)


@dataclass
class VaultFinding:
    """A security or best-practice issue in a Vault configuration file."""

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
class VaultInfo:
    """Parsed metadata about a Vault configuration file."""

    path: str
    has_listener: bool = False
    has_tls: bool = False
    has_seal: bool = False
    storage_type: str = ""
    listeners: int = 0
    lines: int = 0
    blocks: list[str] = field(default_factory=list)


@dataclass
class VaultStats:
    """Aggregate Vault analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_vault_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in VAULT_FILENAMES:
        return True
    if path.suffix.lower() not in (".hcl", ".json"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        VAULT_BLOCK_PATTERN.search(text)
        or LISTENER_BLOCK_PATTERN.search(text)
        or STORAGE_FILE_PATTERN.search(text)
        or STORAGE_RAFT_PATTERN.search(text)
        or re.search(r"\b(?:vault|listener|storage)\s+[\"']", text, re.IGNORECASE)
    )


class VaultAnalyzer:
    """Audit HashiCorp Vault configs for disabled TLS, dev mode, hardcoded tokens, and weak defaults.

    Scans ``vault.hcl``, ``config.hcl``, and related HCL/JSON files for ``tls_disable``,
    ``dev`` blocks, cleartext ``api_addr``, missing seal configuration, and hardcoded unseal keys.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[VaultFinding] | None = None
        self._stats: VaultStats | None = None
        self._infos: list[VaultInfo] | None = None

    def files(self) -> list[Path]:
        """Return Vault configuration files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_vault_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[VaultFinding], VaultInfo]:
        findings: list[VaultFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, VaultInfo(path=rel)

        info = VaultInfo(path=rel, lines=len(raw_lines))
        in_listener = False
        listener_has_tls = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            if LISTENER_BLOCK_PATTERN.match(line):
                in_listener = True
                listener_has_tls = False
                info.has_listener = True
                info.listeners += 1
                if "listener" not in info.blocks:
                    info.blocks.append("listener")

            if in_listener and TLS_CERT_PATTERN.match(line):
                listener_has_tls = True
                info.has_tls = True

            if in_listener and line == "}":
                if not listener_has_tls:
                    findings.append(
                        VaultFinding(
                            kind="listener_no_tls",
                            severity="high",
                            message='listener "tcp" without tls_cert_file/tls_key_file — enable TLS for Vault API',
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                in_listener = False
                listener_has_tls = False

            if STORAGE_FILE_PATTERN.match(line):
                info.storage_type = "file"
                if "storage" not in info.blocks:
                    info.blocks.append("storage")

            if STORAGE_RAFT_PATTERN.match(line):
                info.storage_type = "raft"
                if "storage" not in info.blocks:
                    info.blocks.append("storage")

            if SEAL_BLOCK_PATTERN.match(line):
                info.has_seal = True
                if "seal" not in info.blocks:
                    info.blocks.append("seal")

            if TLS_DISABLE_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="tls_disabled",
                        severity="high",
                        message="tls_disable = true exposes Vault API over cleartext — enable TLS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DISABLE_MLOCK_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="disable_mlock",
                        severity="medium",
                        message="disable_mlock = true allows memory swapping — keep mlock enabled in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RAW_STORAGE_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="raw_storage_endpoint",
                        severity="high",
                        message="raw_storage_endpoint = true exposes raw storage — disable in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UI_ENABLED_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="ui_enabled",
                        severity="low",
                        message="ui = true enables Vault web UI — restrict access or disable in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DEV_MODE_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="dev_mode",
                        severity="high",
                        message="dev { } block enables in-memory dev server — never use in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DEV_ROOT_TOKEN_PATTERN.match(line):
                findings.append(
                    VaultFinding(
                        kind="dev_root_token",
                        severity="high",
                        message="hardcoded dev_root_token_id — remove dev tokens from config files",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    VaultFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret or token in Vault config — use env vars or auto-unseal",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    VaultFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP address in Vault config — use HTTPS for api_addr and cluster_addr",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            lease_match = LONG_LEASE_PATTERN.match(line)
            if lease_match:
                hours = int(lease_match.group(1))
                if hours >= 720:
                    findings.append(
                        VaultFinding(
                            kind="long_lease_ttl",
                            severity="medium",
                            message=f"lease TTL {hours}h exceeds 30 days — shorten default/max lease TTL",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if PLUGIN_DIR_PATTERN.match(line) and "/tmp" in line.lower():
                findings.append(
                    VaultFinding(
                        kind="writable_plugin_dir",
                        severity="medium",
                        message="plugin_directory points to writable path — use a restricted directory",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if TELEMETRY_DISABLED_PATTERN.search(line):
                findings.append(
                    VaultFinding(
                        kind="unauthenticated_metrics",
                        severity="medium",
                        message="unauthenticated_metrics_access = true exposes metrics without auth",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if raw_lines and info.has_listener and not info.has_tls:
            findings.append(
                VaultFinding(
                    kind="missing_tls_certs",
                    severity="high",
                    message="Vault listener configured without TLS certificates",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and info.storage_type in ("file", "raft") and not info.has_seal:
            findings.append(
                VaultFinding(
                    kind="missing_seal",
                    severity="medium",
                    message="no auto-unseal seal block — configure cloud KMS seal for production HA",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[VaultFinding]:
        """Scan Vault configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VaultFinding] = []
        infos: list[VaultInfo] = []
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
        self._stats = VaultStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VaultStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VaultInfo]:
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
        """Scaffold a hardened Vault server configuration template."""
        return """\
# Hardened Vault server configuration template
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/etc/vault/tls/vault.crt"
  tls_key_file    = "/etc/vault/tls/vault.key"
  tls_min_version = "tls12"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}

api_addr     = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"

ui                   = false
disable_mlock        = false
default_lease_ttl    = "1h"
max_lease_ttl        = "24h"
raw_storage_endpoint = false

telemetry {
  unauthenticated_metrics_access = false
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Vault: none found"
        return (
            f"Vault: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Vault config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: storage={info.storage_type or 'unknown'}, "
                f"listeners={info.listeners}, seal={info.has_seal}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
