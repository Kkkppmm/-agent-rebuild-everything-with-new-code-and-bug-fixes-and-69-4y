"""AnsibleAnalyzer — audit Ansible playbooks for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
SHELL_TASK_PATTERN = re.compile(r"^\s*(?:-\s*)?shell:\s*", re.IGNORECASE)
COMMAND_TASK_PATTERN = re.compile(r"^\s*(?:-\s*)?command:\s*", re.IGNORECASE)
BECOME_ROOT_PATTERN = re.compile(r"^\s*become:\s*true\b", re.IGNORECASE)
WEAK_MODE_PATTERN = re.compile(r"^\s*mode:\s*['\"]?(0777|0666|0660)['\"]?\s*$", re.IGNORECASE)
NO_CHECK_MODE_PATTERN = re.compile(r"^\s*check_mode:\s*false\b", re.IGNORECASE)
UNSAFE_VAR_PATTERN = re.compile(r"\{\{\s*[^}]*\}\}", re.IGNORECASE)
SHELL_INJECTION_PATTERN = re.compile(
    r"(shell|command):\s*.*\{\{",
    re.IGNORECASE,
)
BECOME_PASSWORD_INLINE_PATTERN = re.compile(
    r"ansible_become_password\s*:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)


@dataclass
class AnsibleFinding:
    """A security or best-practice issue in an Ansible playbook."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class AnsibleInfo:
    """Parsed metadata about an Ansible playbook."""

    path: str
    plays: int = 0
    tasks: int = 0
    has_become: bool = False
    lines: int = 0


@dataclass
class AnsibleStats:
    """Aggregate Ansible analysis statistics."""

    playbooks: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_ansible_file(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith((".yml", ".yaml")):
        if "playbook" in name or "ansible" in name:
            return True
        if path.parent.name in ("ansible", "playbooks", "roles"):
            return True
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:500]
            return "hosts:" in text and ("tasks:" in text or "roles:" in text)
        except OSError:
            return False
    return False


class AnsibleAnalyzer:
    """Audit Ansible playbooks for hardcoded secrets, unsafe shell tasks, and weak file modes."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AnsibleFinding] | None = None
        self._stats: AnsibleStats | None = None
        self._infos: list[AnsibleInfo] | None = None

    def playbook_files(self) -> list[Path]:
        """Return Ansible playbook paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_ansible_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AnsibleFinding], AnsibleInfo]:
        findings: list[AnsibleFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AnsibleInfo(path=rel)

        info = AnsibleInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("- hosts:") or line.startswith("hosts:"):
                info.plays += 1

            if line.startswith("- name:") or line.startswith("name:"):
                info.tasks += 1

            if BECOME_ROOT_PATTERN.search(line):
                info.has_become = True

            if SECRET_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in playbook",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if BECOME_PASSWORD_INLINE_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="inline_become_password",
                        severity="high",
                        message="Become password hardcoded in playbook",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if SHELL_TASK_PATTERN.search(raw) or COMMAND_TASK_PATTERN.search(raw):
                if SHELL_INJECTION_PATTERN.search(line) or UNSAFE_VAR_PATTERN.search(line):
                    findings.append(
                        AnsibleFinding(
                            kind="shell_injection",
                            severity="high",
                            message="Shell/command task with variable interpolation — injection risk",
                            path=rel,
                            lineno=lineno,
                            line=line[:120],
                        )
                    )
                else:
                    findings.append(
                        AnsibleFinding(
                            kind="shell_task",
                            severity="medium",
                            message="Shell/command task — prefer Ansible modules when possible",
                            path=rel,
                            lineno=lineno,
                            line=line[:120],
                        )
                    )

            if WEAK_MODE_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="weak_file_mode",
                        severity="high",
                        message="Overly permissive file mode (0777/0666/0660)",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if NO_CHECK_MODE_PATTERN.search(line):
                findings.append(
                    AnsibleFinding(
                        kind="check_mode_disabled",
                        severity="low",
                        message="check_mode disabled — changes applied without dry-run",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

        return findings, info

    def analyze(self) -> list[AnsibleFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[AnsibleFinding] = []
        infos: list[AnsibleInfo] = []
        paths = self.playbook_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = AnsibleStats(
            playbooks=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AnsibleStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AnsibleInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.playbooks == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.playbooks == 0:
            return "Ansible: none found"
        return (
            f"Ansible: {stats.playbooks} playbook(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Ansible playbook analysis:",
            f"  playbooks: {stats.playbooks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
