"""TerragruntAnalyzer — audit Terragrunt HCL files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TERRAGRUNT_FILENAMES = (
    "terragrunt.hcl",
    "root.hcl",
    "common.hcl",
)
TERRAGRUNT_SUFFIXES = (".hcl",)
TERRAGRUNT_BLOCK_PATTERN = re.compile(
    r"\b(?:remote_state|terraform\s*\{|include\s*\{|dependency\s+\w+|inputs\s*=\s*\{)\b",
    re.IGNORECASE,
)
REMOTE_STATE_PATTERN = re.compile(r"\bremote_state\s*\{", re.IGNORECASE)
LOCAL_BACKEND_PATTERN = re.compile(r'\bbackend\s*=\s*["\']local["\']', re.IGNORECASE)
HTTP_BACKEND_PATTERN = re.compile(
    r'\bbackend\s*=\s*["\']http["\']|address\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)',
    re.IGNORECASE,
)
ENCRYPTION_DISABLED_PATTERN = re.compile(r"\bencrypt\s*=\s*false\b", re.IGNORECASE)
SKIP_VERSIONING_PATTERN = re.compile(r"\bskip_bucket_versioning\s*=\s*true\b", re.IGNORECASE)
MISSING_LOCK_PATTERN = re.compile(r"\bdynamodb_table\s*=", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key)\s*=\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
MOCK_OUTPUTS_PATTERN = re.compile(r"\bmock_outputs\s*=\s*\{", re.IGNORECASE)
MOCK_OUTPUTS_UNRESTRICTED_PATTERN = re.compile(
    r"mock_outputs_allowed_terraform_commands\s*=\s*\[\s*\]",
    re.IGNORECASE,
)
SKIP_OUTPUTS_PATTERN = re.compile(r"\bskip_outputs\s*=\s*true\b", re.IGNORECASE)
WILDCARD_IAM_PATTERN = re.compile(
    r"(?:iam_role|role_arn|assume_role)\s*=\s*[\"'][^\"']*\*[^\"']*[\"']",
    re.IGNORECASE,
)
GENERATE_PROVIDER_PATTERN = re.compile(r'\bgenerate\s+"provider"', re.IGNORECASE)
GENERATE_CREDENTIAL_PATTERN = re.compile(
    r"(?:access_key|secret_key|aws_access_key_id|aws_secret_access_key)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
PREVENT_DESTROY_FALSE_PATTERN = re.compile(r"\bprevent_destroy\s*=\s*false\b", re.IGNORECASE)
DISABLE_BUCKET_UPDATE_PATTERN = re.compile(r"\bdisable_bucket_update\s*=\s*true\b", re.IGNORECASE)
INSECURE_HTTP_SOURCE_PATTERN = re.compile(
    r'(?:source|url|address)\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)[^\s"\']+',
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
TERRAFORM_SOURCE_PATTERN = re.compile(
    r'terraform\s*\{[^}]*source\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
UNPINNED_SOURCE_PATTERN = re.compile(
    r'source\s*=\s*["\'](?:git::)?(?:https?://|git@)[^"\']*(?:\.git)?(?://)?[^"\']*["\']',
    re.IGNORECASE,
)
REF_PIN_PATTERN = re.compile(r"(?:\?ref=|//)[^\"'?]+(?:\?ref=|//)[^\"']+", re.IGNORECASE)


@dataclass
class TerragruntFinding:
    """A security or best-practice issue in a Terragrunt HCL file."""

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
class TerragruntInfo:
    """Parsed metadata about a Terragrunt HCL file."""

    path: str
    has_remote_state: bool = False
    backend: str = ""
    terraform_source: str = ""
    dependencies: list[str] = field(default_factory=list)
    includes: int = 0
    lines: int = 0


@dataclass
class TerragruntStats:
    """Aggregate Terragrunt analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_terragrunt_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in (name.lower() for name in TERRAGRUNT_FILENAMES):
        return True
    if path.suffix.lower() not in TERRAGRUNT_SUFFIXES:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(TERRAGRUNT_BLOCK_PATTERN.search(text))


class TerragruntAnalyzer:
    """Audit Terragrunt HCL for hardcoded secrets, insecure remote state, and risky dependencies.

    Scans ``terragrunt.hcl`` and related HCL files for plaintext credentials, HTTP backends,
    missing state locking, disabled S3 encryption, unrestricted mock outputs, and wildcard IAM roles.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[TerragruntFinding] | None = None
        self._stats: TerragruntStats | None = None
        self._infos: list[TerragruntInfo] | None = None

    def files(self) -> list[Path]:
        """Return Terragrunt HCL files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_terragrunt_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TerragruntFinding], TerragruntInfo]:
        findings: list[TerragruntFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TerragruntInfo(path=rel)

        text = "\n".join(raw_lines)
        info = TerragruntInfo(path=rel, lines=len(raw_lines))

        if REMOTE_STATE_PATTERN.search(text):
            info.has_remote_state = True
            backend_match = re.search(r'\bbackend\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
            if backend_match:
                info.backend = backend_match.group(1)

        source_match = TERRAFORM_SOURCE_PATTERN.search(text)
        if source_match:
            info.terraform_source = source_match.group(1)

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            dep_match = re.search(r'dependency\s+"([^"]+)"', stripped, re.IGNORECASE)
            if dep_match:
                dep = dep_match.group(1)
                if dep not in info.dependencies:
                    info.dependencies.append(dep)

            if re.search(r"\binclude\s*\{", stripped, re.IGNORECASE):
                info.includes += 1

            if AWS_ACCESS_KEY_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use IAM roles or environment variables",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Terragrunt config — use env vars or a secrets manager",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HTTP_BACKEND_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="insecure_http_backend",
                        severity="high",
                        message="HTTP remote state backend — use S3/GCS with TLS and encryption",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LOCAL_BACKEND_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="local_backend",
                        severity="medium",
                        message="local Terraform backend — use remote state with locking for team workflows",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if ENCRYPTION_DISABLED_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="remote state encryption disabled — enable encrypt = true on S3 backend",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SKIP_VERSIONING_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="skip_bucket_versioning",
                        severity="medium",
                        message="skip_bucket_versioning = true — state bucket versioning aids recovery",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if DISABLE_BUCKET_UPDATE_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="disable_bucket_update",
                        severity="low",
                        message="disable_bucket_update = true — may block security hardening of state bucket",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if MOCK_OUTPUTS_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="mock_outputs",
                        severity="medium",
                        message="mock_outputs in dependency — restrict mock_outputs_allowed_terraform_commands",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if MOCK_OUTPUTS_UNRESTRICTED_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="mock_outputs_unrestricted",
                        severity="high",
                        message="mock_outputs_allowed_terraform_commands is empty — mocks may apply in apply/destroy",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SKIP_OUTPUTS_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="skip_outputs",
                        severity="low",
                        message="skip_outputs = true — verify downstream modules receive required values",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if WILDCARD_IAM_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="wildcard_iam_role",
                        severity="high",
                        message="wildcard in IAM role ARN — scope to specific account and role names",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if GENERATE_PROVIDER_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="generated_provider",
                        severity="low",
                        message="generate \"provider\" block — ensure generated credentials use IAM roles, not keys",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if GENERATE_CREDENTIAL_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="generated_credential",
                        severity="high",
                        message="hardcoded credential in generate block — use IAM instance/profile credentials",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PREVENT_DESTROY_FALSE_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="prevent_destroy_disabled",
                        severity="medium",
                        message="prevent_destroy = false — critical resources should guard against accidental deletion",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_SOURCE_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="insecure_http_source",
                        severity="medium",
                        message="module/source fetched over HTTP — use HTTPS or pinned git refs",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(stripped):
                findings.append(
                    TerragruntFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script integrity before execution",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if info.has_remote_state and info.backend.lower() == "s3" and not MISSING_LOCK_PATTERN.search(text):
            findings.append(
                TerragruntFinding(
                    kind="missing_state_lock",
                    severity="high",
                    message="S3 remote state without dynamodb_table — enable state locking to prevent corruption",
                    path=rel,
                    lineno=1,
                    line="remote_state { backend = \"s3\" ... }",
                )
            )

        if (
            info.terraform_source
            and UNPINNED_SOURCE_PATTERN.search(f'source = "{info.terraform_source}"')
            and not REF_PIN_PATTERN.search(info.terraform_source)
            and "?ref=" not in info.terraform_source
            and "//" not in info.terraform_source.split(".git")[-1]
        ):
            findings.append(
                TerragruntFinding(
                    kind="unpinned_module_source",
                    severity="medium",
                    message=f"terraform source '{info.terraform_source}' has no ref pin — pin to a tag or commit",
                    path=rel,
                    lineno=1,
                    line=f'source = "{info.terraform_source}"',
                )
            )

        if not info.has_remote_state and TERRAGRUNT_BLOCK_PATTERN.search(text):
            findings.append(
                TerragruntFinding(
                    kind="missing_remote_state",
                    severity="medium",
                    message="no remote_state block — configure remote backend with encryption and locking",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TerragruntFinding]:
        """Scan Terragrunt HCL files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TerragruntFinding] = []
        infos: list[TerragruntInfo] = []
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
        self._stats = TerragruntStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TerragruntStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TerragruntInfo]:
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
        """Scaffold a hardened terragrunt.hcl template."""
        return """\
# Hardened terragrunt.hcl template
remote_state {
  backend = "s3"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    bucket         = get_env("TG_STATE_BUCKET", "my-org-terraform-state")
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = get_env("AWS_REGION", "us-east-1")
    encrypt        = true
    dynamodb_table = get_env("TG_LOCK_TABLE", "terraform-locks")
  }
}

terraform {
  source = "git::https://github.com/gruntwork-io/terraform-aws-vpc.git?ref=v3.19.0"
}

inputs = {
  aws_region = get_env("AWS_REGION", "us-east-1")
  # Never hardcode secrets here — use env vars or AWS Secrets Manager
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Terragrunt: none found"
        return (
            f"Terragrunt: {stats.configs} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Terragrunt config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: backend={info.backend or 'none'}, "
                f"source={info.terraform_source or 'none'}, "
                f"dependencies={info.dependencies or 'none'}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
