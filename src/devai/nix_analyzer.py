"""NixAnalyzer — audit flake.nix, shell.nix, and Nix configs for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

NIX_FILE_NAMES = ("flake.nix", "shell.nix", "default.nix", "nix.conf")
NIX_FILE_SUFFIX = ".nix"
NIX_DIRS = ("nix", "modules", "overlays", "pkgs")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:ref|rev|branch|tag)\s*=\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:\?|&)ref=(?:main|master|HEAD|develop|trunk)\b|"
    r"inputs\.[^.]+\.url\s*=\s*[\"'][^\"']*(?:main|master|HEAD|develop|trunk)[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:NIX_SSL_CERT_FILE|ssl_verify|verify_ssl)[\"']?\s*[=:]\s*(?:false|0|off|False|OFF|\"\")|"
    r"curl\s+[^\n]*--insecure\b|"
    r"curl\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
FETCH_TARBALL_PATTERN = re.compile(
    r"builtins\.fetchTarball(?:\s*\(|\s+[\"'])",
    re.IGNORECASE,
)
FETCH_GIT_PATTERN = re.compile(
    r"(?:builtins\.fetchGit|fetchFromGitHub|fetchFromGitLab|fetchgit)\s*\(",
    re.IGNORECASE,
)
IMPORT_URL_PATTERN = re.compile(
    r"import\s*\(\s*(?:fetchurl|builtins\.fetch(?:Tarball|url))\s*\(",
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(
    r"(?:sha256|hash)\s*=\s*[\"'][a-zA-Z0-9+/=_-]{8,}[\"']|"
    r"sha256-[a-zA-Z0-9+/=_-]{8,}",
    re.IGNORECASE,
)
NETRC_CREDENTIAL_PATTERN = re.compile(
    r"(?:machine|login|password)\s+[^\n;]+",
    re.IGNORECASE,
)
NIX_SECRET_JSON_PATTERN = re.compile(
    r"[\"'](?:password|token|api[_-]?key|secret|credential)[\"']\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
SUBSTITUTER_HTTP_PATTERN = re.compile(
    r"(?:substituters|trusted-substituters)\s*=\s*[^\n]*http://",
    re.IGNORECASE,
)
FLAKE_INPUT_PATTERN = re.compile(
    r"inputs\.([a-zA-Z0-9_-]+)\s*=",
    re.IGNORECASE,
)
RUN_COMMAND_PATTERN = re.compile(
    r"(?:pkgs\.)?(?:runCommand|writeShellScriptBin|writeShellScript)\s",
    re.IGNORECASE,
)
IMPURE_ENV_PATTERN = re.compile(
    r"impureEnvVars\s*=\s*\[[^\]]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)",
    re.IGNORECASE,
)


@dataclass
class NixFinding:
    """A security or best-practice issue in a Nix configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NixInfo:
    """Parsed metadata from a Nix configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    inputs: list[str] = field(default_factory=list)


@dataclass
class NixStats:
    """Aggregate statistics from Nix analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_nix_file(path: Path) -> bool:
    name = path.name
    if name in NIX_FILE_NAMES:
        return True
    if path.suffix == NIX_FILE_SUFFIX:
        if any(part in NIX_DIRS for part in path.parts):
            return True
        if name in ("flake.nix", "shell.nix", "default.nix"):
            return True
        if path.parent == path.parents[0] or path.parent.name in NIX_DIRS:
            return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "flake.nix":
        return "flake"
    if name == "shell.nix":
        return "shell"
    if name == "default.nix":
        return "default"
    if name == "nix.conf":
        return "nix.conf"
    if path.suffix == NIX_FILE_SUFFIX:
        return "nix"
    return "unknown"


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith("#") or stripped.startswith("//")


class NixAnalyzer:
    """Audit Nix configuration for security issues.

    Scans flake.nix, shell.nix, default.nix, nix.conf, and module overlays
    for hardcoded secrets, insecure HTTP substituters, credentials in git URLs,
    unpinned flake inputs, disabled TLS verification, unverified fetchTarball
    calls, and dangerous shell scripts in derivations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NixFinding] | None = None
        self._stats: NixStats | None = None
        self._infos: list[NixInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Nix configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_nix_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[NixFinding],
        info: NixInfo,
    ) -> None:
        if _is_comment_line(line):
            return

        input_match = FLAKE_INPUT_PATTERN.search(line)
        if input_match:
            info.inputs.append(input_match.group(1))

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or NIX_SECRET_JSON_PATTERN.search(line)
            or IMPURE_ENV_PATTERN.search(line)
        ):
            findings.append(
                NixFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Nix config — use sops-nix, agenix, or runtime env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Nix config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line) or SUBSTITUTER_HTTP_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL or substituter — use HTTPS for flake inputs and binary caches",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line) or NETRC_CREDENTIAL_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL or netrc — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="flake input or git ref pinned to moving branch — pin to commit SHA in flake.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Nix expression — vendor scripts with hash verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in derivations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep SSL verification enabled for downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and RUN_COMMAND_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="dangerous_shell_command",
                    severity="high",
                    message="dangerous command in runCommand/writeShellScript — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if (
            FETCH_TARBALL_PATTERN.search(line) or FETCH_GIT_PATTERN.search(line)
        ) and not HASH_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="unverified_fetch",
                    severity="medium",
                    message="fetchTarball/fetchGit without sha256 hash — pin content hash for reproducibility",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IMPORT_URL_PATTERN.search(line) and not HASH_PATTERN.search(line):
            findings.append(
                NixFinding(
                    kind="unverified_import",
                    severity="medium",
                    message="import from remote URL without hash — pin fetch with sha256",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[NixFinding], NixInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[NixFinding] = []
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NixInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = NixInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

        return findings, info

    def analyze(self) -> list[NixFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NixFinding] = []
        infos: list[NixInfo] = []
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
        self._stats = NixStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NixStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NixInfo]:
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
        """Scaffold a hardened flake.nix snippet with secure defaults."""
        return """\
{
  description = "Secure Nix flake with pinned inputs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          # Load secrets from the environment — never hardcode in .nix files
          # sops-nix or agenix recommended for production secrets
          packages = with pkgs; [ git curl ];
        };
      });
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Nix configs: none found"
        return (
            f"Nix configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Nix analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            inputs = ", ".join(info.inputs[:8]) if info.inputs else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.inputs)} input(s)"
            )
            lines.append(f"      inputs: {inputs}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
