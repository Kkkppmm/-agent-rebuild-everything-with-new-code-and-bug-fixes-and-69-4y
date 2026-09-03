"""CommitizenAnalyzer — audit Commitizen configs for version-bump and changelog security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (".cz.toml", "cz.toml", "cz.json")
PYPROJECT_NAME = "pyproject.toml"

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True\b", re.IGNORECASE)
COMMITIZEN_SECTION_PATTERN = re.compile(r"^\[tool\.commitizen\]", re.IGNORECASE)
HOOK_KEY_PATTERN = re.compile(
    r"^\s*(?:pre_bump_hooks|post_bump_hooks|changelog_merge_hook|custom_hooks)\s*=",
    re.IGNORECASE,
)
GPG_SIGN_FALSE_PATTERN = re.compile(r"gpg_sign\s*=\s*false\b", re.IGNORECASE)
VERSION_PROVIDER_CUSTOM_PATTERN = re.compile(
    r"version_provider\s*=\s*[\"'](?!commitizen\.version_providers\.)[^\"']+[\"']",
    re.IGNORECASE,
)
TAG_FORMAT_SHELL_PATTERN = re.compile(
    r"tag_format\s*=\s*[\"'][^\"']*(?:\$\(|`|\|\||&&|;)[^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class CommitizenFinding:
    """A security or best-practice issue in a Commitizen configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CommitizenInfo:
    """Parsed metadata about a Commitizen configuration file."""

    path: str
    lines: int = 0
    hooks: list[str] = field(default_factory=list)
    gpg_sign_disabled: bool = False
    version_provider: str = ""


@dataclass
class CommitizenStats:
    """Aggregate Commitizen analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class CommitizenAnalyzer:
    """Audit Commitizen configs for version-bump and changelog security risks.

    Scans pyproject.toml [tool.commitizen], .cz.toml, cz.toml, and cz.json for
    hardcoded secrets, pre/post bump hooks with dangerous commands, unsigned tags,
    custom version providers, insecure HTTP URLs, and SCM credentials.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CommitizenFinding] | None = None
        self._stats: CommitizenStats | None = None
        self._infos: list[CommitizenInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Commitizen configuration paths found in the project."""
        found: list[Path] = []
        pyproject = self.root / PYPROJECT_NAME
        if pyproject.is_file() and self._has_commitizen_section(pyproject):
            found.append(pyproject)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _has_commitizen_section(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "[tool.commitizen" in text.lower()

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CommitizenFinding],
        info: CommitizenInfo,
        in_commitizen_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if in_commitizen_section and GPG_SIGN_FALSE_PATTERN.search(line):
            info.gpg_sign_disabled = True
            findings.append(
                CommitizenFinding(
                    kind="gpg_sign_disabled",
                    severity="low",
                    message="gpg_sign=false — consider signing release tags for supply-chain integrity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_commitizen_section and VERSION_PROVIDER_CUSTOM_PATTERN.search(line):
            provider_match = re.search(
                r"version_provider\s*=\s*[\"']([^\"']+)[\"']",
                line,
                re.IGNORECASE,
            )
            if provider_match:
                info.version_provider = provider_match.group(1)
            findings.append(
                CommitizenFinding(
                    kind="custom_version_provider",
                    severity="medium",
                    message="custom version_provider — review for arbitrary code execution during bumps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_commitizen_section and TAG_FORMAT_SHELL_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="tag_format_shell",
                    severity="medium",
                    message="tag_format contains shell metacharacters — keep formats static",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if not in_commitizen_section:
            return

        if HOOK_KEY_PATTERN.match(stripped):
            hook_match = re.findall(r"[\"']([^\"']+)[\"']", line)
            for hook in hook_match:
                if hook not in info.hooks:
                    info.hooks.append(hook)

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get|\{[A-Z_]+\}", line, re.IGNORECASE):
                findings.append(
                    CommitizenFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Commitizen config — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Commitizen config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Commitizen config — use HTTPS for hooks and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in Commitizen config — review bump hooks carefully",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in Commitizen config — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(line) and ("=" in line or '"' in line or "'" in line):
            findings.append(
                CommitizenFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="hook runs with sudo — prefer least-privilege in release automation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHELL_TRUE_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="shell_true",
                    severity="medium",
                    message="shell=True enables shell injection — pass argument lists instead",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_toml_file(self, path: Path) -> tuple[list[CommitizenFinding], CommitizenInfo]:
        findings: list[CommitizenFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CommitizenInfo(path=rel)

        info = CommitizenInfo(path=rel, lines=len(raw_lines))
        in_commitizen_section = path.name in (".cz.toml", "cz.toml")

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if COMMITIZEN_SECTION_PATTERN.match(stripped):
                in_commitizen_section = True
            elif stripped.startswith("[") and not COMMITIZEN_SECTION_PATTERN.match(stripped):
                in_commitizen_section = False

            self._scan_line(line, lineno, rel, findings, info, in_commitizen_section)

        return findings, info

    def _analyze_json_file(self, path: Path) -> tuple[list[CommitizenFinding], CommitizenInfo]:
        findings: list[CommitizenFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError):
            return findings, CommitizenInfo(path=rel)

        info = CommitizenInfo(path=rel, lines=text.count("\n") + 1)
        config = data.get("commitizen", data.get("tool", {}).get("commitizen", data))
        if not isinstance(config, dict):
            return findings, info

        if config.get("gpg_sign") is False:
            info.gpg_sign_disabled = True
            findings.append(
                CommitizenFinding(
                    kind="gpg_sign_disabled",
                    severity="low",
                    message="gpg_sign=false — consider signing release tags for supply-chain integrity",
                    path=rel,
                    lineno=1,
                    line="gpg_sign: false",
                )
            )

        provider = config.get("version_provider", "")
        if provider and not str(provider).startswith("commitizen.version_providers."):
            info.version_provider = str(provider)
            findings.append(
                CommitizenFinding(
                    kind="custom_version_provider",
                    severity="medium",
                    message="custom version_provider — review for arbitrary code execution during bumps",
                    path=rel,
                    lineno=1,
                    line=f"version_provider: {provider}",
                )
            )

        for hook_key in ("pre_bump_hooks", "post_bump_hooks", "changelog_merge_hook", "custom_hooks"):
            hooks = config.get(hook_key, [])
            if isinstance(hooks, str):
                hooks = [hooks]
            if isinstance(hooks, list):
                for hook in hooks:
                    if isinstance(hook, str) and hook not in info.hooks:
                        info.hooks.append(hook)

        for lineno, line in enumerate(text.splitlines(), start=1):
            self._scan_line(line, lineno, rel, findings, info, in_commitizen_section=True)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[CommitizenFinding], CommitizenInfo]:
        if path.suffix == ".json":
            return self._analyze_json_file(path)
        return self._analyze_toml_file(path)

    def analyze(self) -> list[CommitizenFinding]:
        """Scan Commitizen config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CommitizenFinding] = []
        infos: list[CommitizenInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = CommitizenStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CommitizenStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CommitizenInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened pyproject.toml [tool.commitizen] template."""
        return """\
# Generated by DevAI CommitizenAnalyzer
# Add this section to pyproject.toml

[tool.commitizen]
name = "cz_conventional_commits"
version = "0.1.0"
version_files = ["pyproject.toml:project.version"]
tag_format = "v$version"
update_changelog_on_bump = true
gpg_sign = true
pre_bump_hooks = ["python -m pytest tests"]
post_bump_hooks = []
# Use env vars for tokens instead of hardcoded secrets in hooks
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Commitizen configs: none found"
        return (
            f"Commitizen configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Commitizen analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            hooks = ", ".join(info.hooks) if info.hooks else "none detected"
            gpg = "disabled" if info.gpg_sign_disabled else "enabled/unspecified"
            lines.append(f"  - {info.path}: hooks={hooks}, gpg_sign={gpg}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
