"""AnsibleAnalyzer — audit Ansible playbooks and roles for insecure tasks and hardcoded secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ANSIBLE_DIRS = ("ansible", "playbooks", "roles", "inventory", "group_vars", "host_vars")
ANSIBLE_SUFFIXES = (".yml", ".yaml")
PLAYBOOK_NAMES = ("site.yml", "site.yaml", "playbook.yml", "playbook.yaml")

HARDCODED_PASSWORD_PATTERN = re.compile(
    r"(?:ansible_password|ansible_become_password|password|db_password|secret|token|api_key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
SHELL_MODULE_PATTERN = re.compile(r"^\s*(?:ansible\.builtin\.)?shell\s*:", re.IGNORECASE)
COMMAND_MODULE_PATTERN = re.compile(r"^\s*(?:ansible\.builtin\.)?command\s*:", re.IGNORECASE)
RAW_MODULE_PATTERN = re.compile(r"^\s*raw\s*:", re.IGNORECASE)
BECOME_YES_PATTERN = re.compile(r"^\s*become\s*:\s*(?:yes|true)\s*$", re.IGNORECASE)
BECOME_USER_PATTERN = re.compile(r"^\s*become_user\s*:", re.IGNORECASE)
WORLD_WRITABLE_MODE_PATTERN = re.compile(
    r"^\s*mode\s*:\s*[\"']?0?77[67][67]?[\"']?\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
NO_LOG_FALSE_PATTERN = re.compile(r"^\s*no_log\s*:\s*(?:false|no)\s*$", re.IGNORECASE)
NO_LOG_TRUE_PATTERN = re.compile(r"^\s*no_log\s*:\s*(?:true|yes)\s*$", re.IGNORECASE)
IGNORE_ERRORS_PATTERN = re.compile(r"^\s*ignore_errors\s*:\s*(?:yes|true)\s*$", re.IGNORECASE)
STATE_LATEST_PATTERN = re.compile(
    r"^\s*state\s*:\s*latest\s*$",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"^\s*(?:ansible\.builtin\.)?git\s*:",
    re.IGNORECASE,
)
VERSION_PATTERN = re.compile(r"^\s*version\s*:", re.IGNORECASE)
CREATES_PATTERN = re.compile(r"^\s*creates\s*:", re.IGNORECASE)
REMOVES_PATTERN = re.compile(r"^\s*removes\s*:", re.IGNORECASE)
CHANGED_WHEN_PATTERN = re.compile(r"^\s*changed_when\s*:", re.IGNORECASE)


@dataclass
class AnsibleFinding:
    """A security issue in an Ansible playbook or role file."""

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
class AnsiblePlaybookInfo:
    """Parsed metadata about an Ansible file."""

    path: str
    tasks: int = 0
    roles: int = 0
    lines: int = 0


@dataclass
class AnsibleStats:
    """Aggregate Ansible analysis statistics."""

    playbooks: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_ansible_file(path: Path) -> bool:
    lower = path.name.lower()
    if not lower.endswith(ANSIBLE_SUFFIXES):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(ANSIBLE_DIRS):
        return True
    if lower in PLAYBOOK_NAMES:
        return True
    if "/tasks/" in str(path).lower() or "/handlers/" in str(path).lower():
        return True
    if lower.endswith(ANSIBLE_SUFFIXES) and "ansible" in lower:
        return True
    return False


class AnsibleAnalyzer:
    """Audit Ansible playbooks and roles for hardcoded secrets, unsafe shell tasks, and weak defaults.

    Scans YAML playbooks, role tasks, and inventory files for plaintext credentials,
    shell/command without idempotency guards, world-writable file modes, and curl|bash patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AnsibleFinding] | None = None
        self._stats: AnsibleStats | None = None
        self._infos: list[AnsiblePlaybookInfo] | None = None

    def files(self) -> list[Path]:
        """Return Ansible-related YAML files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_ansible_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AnsibleFinding], AnsiblePlaybookInfo]:
        findings: list[AnsibleFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AnsiblePlaybookInfo(path=rel)

        info = AnsiblePlaybookInfo(path=rel, lines=len(raw_lines))
        task_indent: int | None = None
        has_become_user = False
        has_no_log = False
        has_creates = False
        has_removes = False
        has_changed_when = False
        has_version = False
        shell_task = False
        git_task = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("- name:") or line.startswith("- hosts:"):
                if shell_task and not (has_creates or has_removes or has_changed_when):
                    findings.append(
                        AnsibleFinding(
                            kind="non_idempotent_shell",
                            severity="medium",
                            message="shell/command task without creates, removes, or changed_when",
                            path=rel,
                            lineno=task_indent or lineno,
                            line="",
                        )
                    )
                if git_task and not has_version:
                    findings.append(
                        AnsibleFinding(
                            kind="unpinned_git",
                            severity="low",
                            message="git task without pinned version — pin to a commit or tag",
                            path=rel,
                            lineno=task_indent or lineno,
                            line="",
                        )
                    )
                task_indent = lineno
                has_become_user = False
                has_no_log = False
                has_creates = False
                has_removes = False
                has_changed_when = False
                has_version = False
                shell_task = False
                git_task = False

            if line.startswith("- hosts:"):
                info.tasks += 1
            if line.startswith("- role:") or line.startswith("roles:"):
                info.roles += 1
            if line.startswith("- name:"):
                info.tasks += 1

            if BECOME_YES_PATTERN.search(line):
                pass
            if BECOME_USER_PATTERN.search(line):
                has_become_user = True
            if NO_LOG_TRUE_PATTERN.search(line):
                has_no_log = True
            if CREATES_PATTERN.search(line):
                has_creates = True
            if REMOVES_PATTERN.search(line):
                has_removes = True
            if CHANGED_WHEN_PATTERN.search(line):
                has_changed_when = True
            if VERSION_PATTERN.search(line):
                has_version = True

            if SHELL_MODULE_PATTERN.search(line) or COMMAND_MODULE_PATTERN.search(line):
                shell_task = True
                task_indent = task_indent or lineno
            if RAW_MODULE_PATTERN.search(line):
                shell_task = True
                task_indent = task_indent or lineno
                findings.append(
                    AnsibleFinding(
                        kind="raw_module",
                        severity="high",
                        message="raw module bypasses Ansible safety — prefer a dedicated module",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
            if UNPINNED_GIT_PATTERN.search(line):
                git_task = True
                task_indent = task_indent or lineno

            if HARDCODED_PASSWORD_PATTERN.search(line):
                if not has_no_log:
                    findings.append(
                        AnsibleFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded credential — use Ansible Vault or a secret manager",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if WORLD_WRITABLE_MODE_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="world_writable_mode",
                        severity="high",
                        message="world-writable file mode — use restrictive permissions (e.g. 0644)",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if NO_LOG_FALSE_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="no_log_disabled",
                        severity="medium",
                        message="no_log: false may expose secrets in Ansible output",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if IGNORE_ERRORS_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="ignore_errors",
                        severity="low",
                        message="ignore_errors: true may hide deployment failures",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if STATE_LATEST_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="state_latest",
                        severity="low",
                        message="state: latest reduces reproducibility — pin package versions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BECOME_YES_PATTERN.search(line) and not has_become_user:
                findings.append(
                    AnsibleFinding(
                        kind="become_without_user",
                        severity="medium",
                        message="become enabled without become_user — avoid defaulting to root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if shell_task and not (has_creates or has_removes or has_changed_when):
            findings.append(
                AnsibleFinding(
                    kind="non_idempotent_shell",
                    severity="medium",
                    message="shell/command task without creates, removes, or changed_when",
                    path=rel,
                    lineno=task_indent or len(raw_lines),
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[AnsibleFinding]:
        """Scan Ansible files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AnsibleFinding] = []
        infos: list[AnsiblePlaybookInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        playbook_count = sum(1 for info in infos if info.tasks > 0 or info.roles > 0)
        if playbook_count == 0 and paths:
            playbook_count = len(paths)
        self._stats = AnsibleStats(
            playbooks=playbook_count,
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AnsibleStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AnsiblePlaybookInfo]:
        """Return parsed Ansible file metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no playbooks)."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_task_snippet(self) -> str:
        """Scaffold a hardened Ansible task with Vault and idempotency guards."""
        return """\
# Generated by DevAI AnsibleAnalyzer — hardened task template
- name: Deploy application config
  ansible.builtin.template:
    src: app.conf.j2
    dest: /etc/myapp/app.conf
    owner: myapp
    group: myapp
    mode: "0640"
  become: true
  become_user: myapp
  no_log: true
  vars:
    app_password: "{{ vault_app_password }}"  # store in Ansible Vault

- name: Run database migration
  ansible.builtin.command:
    cmd: /opt/myapp/bin/migrate
    creates: /var/lib/myapp/.migrated
  become: true
  become_user: myapp
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return "Ansible playbooks: none found"
        return (
            f"Ansible: {stats.playbooks} playbook(s), {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Ansible analysis:",
            f"  playbooks: {stats.playbooks}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos[:10]:
            lines.append(f"  - {info.path}: {info.tasks} task(s), {info.roles} role(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
