"""ConsulAnalyzer — audit HashiCorp Consul configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONSUL_FILENAMES = (
    "consul.hcl",
    "consul.json",
    "consul-config.hcl",
    "config.hcl",
)
CONSUL_BLOCK_PATTERN = re.compile(r"^\s*consul\s*\{", re.IGNORECASE)
DATACENTER_PATTERN = re.compile(r'^\s*datacenter\s*=\s*["\']', re.IGNORECASE)
DEV_MODE_PATTERN = re.compile(r"^\s*dev_mode\s*=\s*true\s*$", re.IGNORECASE)
ACL_DISABLED_PATTERN = re.compile(r"^\s*enabled\s*=\s*false\s*$", re.IGNORECASE)
ACL_DEFAULT_ALLOW_PATTERN = re.compile(
    r'^\s*default_policy\s*=\s*["\']allow["\']\s*$',
    re.IGNORECASE,
)
TLS_VERIFY_INCOMING_PATTERN = re.compile(
    r"^\s*verify_incoming\s*=\s*false\s*$",
    re.IGNORECASE,
)
TLS_VERIFY_OUTGOING_PATTERN = re.compile(
    r"^\s*verify_outgoing\s*=\s*false\s*$",
    re.IGNORECASE,
)
TLS_HTTPS_DISABLED_PATTERN = re.compile(
    r"^\s*https\s*=\s*-1\s*$",
    re.IGNORECASE,
)
AUTO_ENCRYPT_DISABLED_PATTERN = re.compile(
    r"^\s*allow_tls\s*=\s*false\s*$",
    re.IGNORECASE,
)
CONNECT_DISABLED_PATTERN = re.compile(
    r"^\s*enabled\s*=\s*false\s*$",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"(?:agent|default|master|replication|agent_master|dns|initial_management)\s*=\s*"
    r'["\'][^"\']{8,}["\']',
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:encrypt|secret|token|password|api[_-]?key)\s*=\s*"
    r'["\'][^"\']{6,}["\']',
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:advertise_addr|retry_join|connect|addresses)\s*=\s*"
    r'["\']?http://(?!localhost|127\.0\.0\.1)[^\s"\']+',
    re.IGNORECASE,
)
UI_ENABLED_PATTERN = re.compile(r"^\s*enabled\s*=\s*true\s*$", re.IGNORECASE)
BIND_ALL_PATTERN = re.compile(
    r'^\s*bind_addr\s*=\s*["\']0\.0\.0\.0["\']\s*$',
    re.IGNORECASE,
)
CLIENT_ADDR_ALL_PATTERN = re.compile(
    r'^\s*client_addr\s*=\s*["\']0\.0\.0\.0["\']\s*$',
    re.IGNORECASE,
)
RPC_HOLD_PATTERN = re.compile(
    r"^\s*rpc_hold_timeout\s*=\s*\"(\d+)s\"",
    re.IGNORECASE,
)


@dataclass
class ConsulFinding:
    """A security or best-practice issue in a Consul configuration file."""

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
class ConsulInfo:
    """Parsed metadata about a Consul configuration file."""

    path: str
    has_acl: bool = False
    has_tls: bool = False
    has_encrypt: bool = False
    connect_enabled: bool = False
    datacenter: str = ""
    lines: int = 0
    blocks: list[str] = field(default_factory=list)


@dataclass
class ConsulStats:
    """Aggregate Consul analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_consul_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CONSUL_FILENAMES:
        return True
    if path.suffix.lower() not in (".hcl", ".json"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        CONSUL_BLOCK_PATTERN.search(text)
        or DATACENTER_PATTERN.search(text)
        or re.search(r"\b(?:consul|datacenter|retry_join|serf_lan)\b", text, re.IGNORECASE)
    )


class ConsulAnalyzer:
    """Audit HashiCorp Consul configs for disabled ACLs/TLS, dev mode, hardcoded tokens, and weak defaults.

    Scans ``consul.hcl``, ``consul.json``, and related HCL/JSON files for ``dev_mode``,
    ``acl { enabled = false }``, cleartext gossip ``encrypt``, disabled TLS verification,
  and hardcoded agent tokens.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[ConsulFinding] | None = None
        self._stats: ConsulStats | None = None
        self._infos: list[ConsulInfo] | None = None

    def files(self) -> list[Path]:
        """Return Consul configuration files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_consul_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[ConsulFinding], ConsulInfo]:
        findings: list[ConsulFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ConsulInfo(path=rel)

        info = ConsulInfo(path=rel, lines=len(raw_lines))
        block_stack: list[str] = []

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            block_match = re.match(r'^\s*(\w+)\s*\{', line, re.IGNORECASE)
            if block_match:
                block_stack.append(block_match.group(1).lower())

            if line == "}":
                if block_stack:
                    block_stack.pop()

            current_blocks = set(block_stack)
            in_acl = "acl" in current_blocks
            in_tls = "tls" in current_blocks
            in_ports = "ports" in current_blocks
            in_auto_encrypt = "auto_encrypt" in current_blocks
            in_connect = "connect" in current_blocks
            in_ui = "ui_config" in current_blocks or "ui" in current_blocks
            in_tokens = "tokens" in current_blocks

            if DATACENTER_PATTERN.match(line):
                dc_match = re.search(r'=\s*["\']([^"\']+)["\']', line)
                if dc_match:
                    info.datacenter = dc_match.group(1)

            if re.match(r'^\s*acl\s*\{', line, re.IGNORECASE):
                info.has_acl = True
                if "acl" not in info.blocks:
                    info.blocks.append("acl")

            if re.match(r'^\s*tls\s*\{', line, re.IGNORECASE):
                info.has_tls = True
                if "tls" not in info.blocks:
                    info.blocks.append("tls")

            if re.match(r'^\s*encrypt\s*=', line, re.IGNORECASE):
                info.has_encrypt = True
                if "encrypt" not in info.blocks:
                    info.blocks.append("encrypt")

            if re.match(r'^\s*connect\s*\{', line, re.IGNORECASE):
                if "connect" not in info.blocks:
                    info.blocks.append("connect")

            if DEV_MODE_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="dev_mode",
                        severity="high",
                        message="dev_mode = true enables in-memory dev server — never use in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_acl and ACL_DISABLED_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="acl_disabled",
                        severity="high",
                        message="acl { enabled = false } disables access control — enable ACLs in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_acl and ACL_DEFAULT_ALLOW_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="acl_default_allow",
                        severity="high",
                        message='acl default_policy = "allow" permits all traffic — use "deny" with explicit rules',
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_VERIFY_INCOMING_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="tls_verify_incoming_disabled",
                        severity="high",
                        message="tls verify_incoming = false disables client certificate verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_VERIFY_OUTGOING_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="tls_verify_outgoing_disabled",
                        severity="medium",
                        message="tls verify_outgoing = false disables server certificate verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_ports and TLS_HTTPS_DISABLED_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="https_disabled",
                        severity="high",
                        message="ports https = -1 disables HTTPS API — enable TLS on the HTTP API",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_auto_encrypt and AUTO_ENCRYPT_DISABLED_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="auto_encrypt_disabled",
                        severity="medium",
                        message="auto_encrypt allow_tls = false disables automatic TLS for RPC",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_connect and CONNECT_DISABLED_PATTERN.match(line):
                info.connect_enabled = False
                findings.append(
                    ConsulFinding(
                        kind="connect_disabled",
                        severity="medium",
                        message="connect { enabled = false } disables service mesh mTLS — enable Connect",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
            elif in_connect and re.match(r"^\s*enabled\s*=\s*true\s*$", line, re.IGNORECASE):
                info.connect_enabled = True

            if in_ui and UI_ENABLED_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="ui_enabled",
                        severity="low",
                        message="Consul UI enabled — restrict access or disable in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_tokens or in_acl) and HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    ConsulFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="hardcoded Consul ACL token — use env vars or Vault integration",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) and not line.startswith("encrypt"):
                if "encrypt" in line.lower() and '"' in line:
                    findings.append(
                        ConsulFinding(
                            kind="hardcoded_encrypt_key",
                            severity="high",
                            message="hardcoded gossip encrypt key — rotate and store in secrets manager",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ConsulFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP address in Consul config — use HTTPS for cluster communication",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BIND_ALL_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="bind_all_interfaces",
                        severity="medium",
                        message='bind_addr = "0.0.0.0" exposes Consul on all interfaces — bind to specific address',
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CLIENT_ADDR_ALL_PATTERN.match(line):
                findings.append(
                    ConsulFinding(
                        kind="client_addr_all",
                        severity="medium",
                        message='client_addr = "0.0.0.0" exposes client API on all interfaces — restrict access',
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            hold_match = RPC_HOLD_PATTERN.match(line)
            if hold_match and int(hold_match.group(1)) > 60:
                findings.append(
                    ConsulFinding(
                        kind="long_rpc_hold_timeout",
                        severity="low",
                        message=f"rpc_hold_timeout {hold_match.group(1)}s exceeds 60s — shorten for faster failover",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if raw_lines and not info.has_acl:
            findings.append(
                ConsulFinding(
                    kind="missing_acl",
                    severity="medium",
                    message="no acl block — enable ACLs with default_policy = deny for production",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and not info.has_encrypt:
            findings.append(
                ConsulFinding(
                    kind="missing_encrypt",
                    severity="high",
                    message="no gossip encrypt key — enable gossip encryption for cluster traffic",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[ConsulFinding]:
        """Scan Consul configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ConsulFinding] = []
        infos: list[ConsulInfo] = []
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
        self._stats = ConsulStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ConsulStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ConsulInfo]:
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
        """Scaffold a hardened Consul server configuration template."""
        return """\
# Hardened Consul server configuration template
datacenter = "dc1"
data_dir   = "/opt/consul/data"

encrypt = "${CONSUL_GOSSIP_KEY}"

acl {
  enabled        = true
  default_policy = "deny"
  enable_token_persistence = true
}

tls {
  defaults {
    verify_incoming  = true
    verify_outgoing  = true
    ca_file          = "/etc/consul/tls/consul-agent-ca.pem"
    cert_file        = "/etc/consul/tls/dc1-server-consul-0.pem"
    private_key_file = "/etc/consul/tls/dc1-server-consul-0-key.pem"
  }
}

ports {
  http  = -1
  https = 8501
}

auto_encrypt {
  allow_tls = true
}

connect {
  enabled = true
}

ui_config {
  enabled = false
}

bind_addr    = "10.0.0.10"
client_addr  = "127.0.0.1"
advertise_addr = "10.0.0.10"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Consul: none found"
        return (
            f"Consul: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Consul config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: datacenter={info.datacenter or 'unknown'}, "
                f"acl={info.has_acl}, encrypt={info.has_encrypt}, connect={info.connect_enabled}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
