"""NomadAnalyzer — audit HashiCorp Nomad configuration files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NOMAD_FILENAMES = (
    "nomad.hcl",
    "nomad.json",
    "nomad-config.hcl",
    "agent.hcl",
)
NOMAD_BLOCK_PATTERN = re.compile(r"^\s*nomad\s*\{", re.IGNORECASE)
DATACENTER_PATTERN = re.compile(r'^\s*datacenter\s*=\s*["\']', re.IGNORECASE)
DEV_BLOCK_PATTERN = re.compile(r"^\s*dev\s*\{", re.IGNORECASE)
DEV_MODE_PATTERN = re.compile(r"^\s*dev_mode\s*=\s*true\s*$", re.IGNORECASE)
ACL_DISABLED_PATTERN = re.compile(r"^\s*enabled\s*=\s*false\s*$", re.IGNORECASE)
ACL_DEFAULT_ALLOW_PATTERN = re.compile(
    r'^\s*default_policy\s*=\s*["\']allow["\']\s*$',
    re.IGNORECASE,
)
TLS_HTTP_DISABLED_PATTERN = re.compile(r"^\s*http\s*=\s*false\s*$", re.IGNORECASE)
TLS_RPC_DISABLED_PATTERN = re.compile(r"^\s*rpc\s*=\s*false\s*$", re.IGNORECASE)
TLS_VERIFY_HOSTNAME_DISABLED_PATTERN = re.compile(
    r"^\s*verify_server_hostname\s*=\s*false\s*$",
    re.IGNORECASE,
)
TLS_VERIFY_CLIENT_DISABLED_PATTERN = re.compile(
    r"^\s*verify_https_client\s*=\s*false\s*$",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"(?:agent|management|replication|default)\s*=\s*"
    r'["\'][^"\']{8,}["\']',
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:token|secret|password|api[_-]?key)\s*=\s*"
    r'["\'][^"\']{6,}["\']',
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:address|advertise|api_addr|consul|vault)\s*=\s*"
    r'["\']?http://(?!localhost|127\.0\.0\.1)[^\s"\']+',
    re.IGNORECASE,
)
UI_ENABLED_PATTERN = re.compile(r"^\s*enabled\s*=\s*true\s*$", re.IGNORECASE)
BIND_ALL_PATTERN = re.compile(
    r'^\s*bind_addr\s*=\s*["\']0\.0\.0\.0["\']\s*$',
    re.IGNORECASE,
)
ALLOW_PRIVILEGED_PATTERN = re.compile(
    r"^\s*allow_privileged\s*=\s*true\s*$",
    re.IGNORECASE,
)
RAW_EXEC_ENABLED_PATTERN = re.compile(
    r"^\s*enabled\s*=\s*true\s*$",
    re.IGNORECASE,
)
HOST_VOLUME_ENABLED_PATTERN = re.compile(
    r"^\s*enabled\s*=\s*true\s*$",
    re.IGNORECASE,
)


@dataclass
class NomadFinding:
    """A security or best-practice issue in a Nomad configuration file."""

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
class NomadInfo:
    """Parsed metadata about a Nomad configuration file."""

    path: str
    has_acl: bool = False
    has_tls: bool = False
    has_vault: bool = False
    has_consul: bool = False
    server_enabled: bool = False
    client_enabled: bool = False
    datacenter: str = ""
    lines: int = 0
    blocks: list[str] = field(default_factory=list)


@dataclass
class NomadStats:
    """Aggregate Nomad analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_nomad_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in NOMAD_FILENAMES:
        return True
    if path.suffix.lower() not in (".hcl", ".json"):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        NOMAD_BLOCK_PATTERN.search(text)
        or DATACENTER_PATTERN.search(text)
        or re.search(
            r"\b(?:nomad|datacenter|job|client|server|consul)\b",
            text,
            re.IGNORECASE,
        )
        and re.search(r"\b(?:data_dir|region|bind_addr)\b", text, re.IGNORECASE)
    )


class NomadAnalyzer:
    """Audit HashiCorp Nomad configs for disabled ACLs/TLS, dev mode, privileged plugins, and weak defaults.

    Scans ``nomad.hcl``, ``agent.hcl``, and related HCL/JSON files for ``dev`` blocks,
    ``acl { enabled = false }``, disabled TLS, ``allow_privileged`` docker plugins,
    raw_exec drivers, and hardcoded management tokens.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[NomadFinding] | None = None
        self._stats: NomadStats | None = None
        self._infos: list[NomadInfo] | None = None

    def files(self) -> list[Path]:
        """Return Nomad configuration files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_nomad_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[NomadFinding], NomadInfo]:
        findings: list[NomadFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, NomadInfo(path=rel)

        info = NomadInfo(path=rel, lines=len(raw_lines))
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
            in_vault = "vault" in current_blocks
            in_consul = "consul" in current_blocks
            in_server = "server" in current_blocks
            in_client = "client" in current_blocks
            in_ui = "ui" in current_blocks
            in_tokens = "tokens" in current_blocks
            in_plugin = "plugin" in current_blocks or "docker" in current_blocks
            in_raw_exec = "raw_exec" in current_blocks
            in_host_volume = "host_volume" in current_blocks

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

            if re.match(r'^\s*vault\s*\{', line, re.IGNORECASE):
                info.has_vault = True
                if "vault" not in info.blocks:
                    info.blocks.append("vault")

            if re.match(r'^\s*consul\s*\{', line, re.IGNORECASE):
                info.has_consul = True
                if "consul" not in info.blocks:
                    info.blocks.append("consul")

            if in_server and re.match(r"^\s*enabled\s*=\s*true\s*$", line, re.IGNORECASE):
                info.server_enabled = True

            if in_client and re.match(r"^\s*enabled\s*=\s*true\s*$", line, re.IGNORECASE):
                info.client_enabled = True

            if DEV_BLOCK_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="dev_block",
                        severity="high",
                        message="dev { } block enables in-memory dev agent — never use in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DEV_MODE_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="dev_mode",
                        severity="high",
                        message="dev_mode = true enables in-memory dev agent — never use in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_acl and ACL_DISABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
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
                    NomadFinding(
                        kind="acl_default_allow",
                        severity="high",
                        message='acl default_policy = "allow" permits all traffic — use "deny" with explicit rules',
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_HTTP_DISABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="tls_http_disabled",
                        severity="high",
                        message="tls http = false disables HTTPS on the HTTP API — enable TLS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_RPC_DISABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="tls_rpc_disabled",
                        severity="high",
                        message="tls rpc = false disables TLS on RPC — enable encrypted cluster communication",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_VERIFY_HOSTNAME_DISABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="tls_verify_hostname_disabled",
                        severity="medium",
                        message="tls verify_server_hostname = false disables hostname verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_tls and TLS_VERIFY_CLIENT_DISABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="tls_verify_client_disabled",
                        severity="medium",
                        message="tls verify_https_client = false disables client certificate verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_plugin and ALLOW_PRIVILEGED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="allow_privileged",
                        severity="high",
                        message="allow_privileged = true permits privileged containers — disable unless required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_raw_exec and RAW_EXEC_ENABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="raw_exec_enabled",
                        severity="high",
                        message="raw_exec driver enabled — disable to prevent host command execution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_host_volume and HOST_VOLUME_ENABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="host_volume_enabled",
                        severity="medium",
                        message="host_volume enabled — restrict paths and ACLs to prevent host filesystem access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_ui and UI_ENABLED_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="ui_enabled",
                        severity="low",
                        message="Nomad UI enabled — restrict access or disable in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_tokens or in_acl) and HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    NomadFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="hardcoded Nomad ACL token — use env vars or Vault integration",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) and "token" in line.lower():
                findings.append(
                    NomadFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Nomad config — store in Vault or secrets manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    NomadFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP address in Nomad config — use HTTPS for cluster communication",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BIND_ALL_PATTERN.match(line):
                findings.append(
                    NomadFinding(
                        kind="bind_all_interfaces",
                        severity="medium",
                        message='bind_addr = "0.0.0.0" exposes Nomad on all interfaces — bind to specific address',
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if raw_lines and not info.has_acl:
            findings.append(
                NomadFinding(
                    kind="missing_acl",
                    severity="medium",
                    message="no acl block — enable ACLs with default_policy = deny for production",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and not info.has_tls:
            findings.append(
                NomadFinding(
                    kind="missing_tls",
                    severity="high",
                    message="no tls block — enable TLS on HTTP and RPC for production clusters",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[NomadFinding]:
        """Scan Nomad configuration files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NomadFinding] = []
        infos: list[NomadInfo] = []
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
        self._stats = NomadStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NomadStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NomadInfo]:
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
        """Scaffold a hardened Nomad server/client configuration template."""
        return """\
# Hardened Nomad agent configuration template
datacenter = "dc1"
data_dir   = "/opt/nomad/data"
region     = "global"

server {
  enabled = true
}

client {
  enabled = true
}

acl {
  enabled        = true
  default_policy = "deny"
}

tls {
  http                   = true
  rpc                    = true
  ca_file                = "/etc/nomad/tls/nomad-agent-ca.pem"
  cert_file              = "/etc/nomad/tls/global-server-nomad.pem"
  key_file               = "/etc/nomad/tls/global-server-nomad-key.pem"
  verify_server_hostname = true
  verify_https_client    = true
}

vault {
  enabled = true
  address = "https://vault.service.consul:8200"
}

consul {
  address = "127.0.0.1:8501"
}

plugin "docker" {
  config {
    allow_privileged = false
  }
}

ui {
  enabled = false
}

bind_addr = "10.0.0.20"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nomad: none found"
        return (
            f"Nomad: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Nomad config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: datacenter={info.datacenter or 'unknown'}, "
                f"acl={info.has_acl}, tls={info.has_tls}, vault={info.has_vault}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
