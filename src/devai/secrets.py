"""SecretsScanner — heuristic detection of hardcoded secrets in code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

DEFAULT_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][^'\"]{20,}['\"]")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36,}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe_key", re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
    ("generic_secret", re.compile(r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

FALSE_POSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(example|placeholder|changeme|your[_-]?api[_-]?key|xxx+|dummy|test|sample|fake)\b"),
    re.compile(r"(?i)_(here|now)\b"),
    re.compile(r"\$\{[^}]+\}"),  # template variables
    re.compile(r"<[^>]+>"),  # XML/HTML placeholders
]


@dataclass
class SecretFinding:
    """A potential secret found in source code."""

    kind: str
    path: str
    lineno: int
    snippet: str
    confidence: str = "medium"

    def format(self) -> str:
        """Return a single-line description of the finding."""
        return f"[{self.kind}] {self.path}:{self.lineno} — {self.snippet}"


class SecretsScanner:
    """Scan files for hardcoded secrets using heuristic patterns."""

    def __init__(
        self,
        root: str,
        *,
        extensions: set[str] | None = None,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.extensions = extensions or set(DEFAULT_EXTENSIONS)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SecretFinding] = []

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)

    def _is_false_positive(self, line: str) -> bool:
        return any(pattern.search(line) for pattern in FALSE_POSITIVE_PATTERNS)

    def _scan_line(
        self,
        line: str,
        path: str,
        lineno: int,
    ) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        if self._is_false_positive(line):
            return findings

        stripped = line.strip()
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                snippet = stripped[:80] + ("..." if len(stripped) > 80 else "")
                confidence = "high" if kind in {"aws_access_key", "github_token", "private_key", "jwt"} else "medium"
                findings.append(
                    SecretFinding(
                        kind=kind,
                        path=path,
                        lineno=lineno,
                        snippet=snippet,
                        confidence=confidence,
                    )
                )
        return findings

    def scan_text(self, text: str, path: str = "<string>") -> list[SecretFinding]:
        """Scan a text blob for potential secrets."""
        findings: list[SecretFinding] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            findings.extend(self._scan_line(line, path, lineno))
        return findings

    def scan_file(self, path: str | Path) -> list[SecretFinding]:
        """Scan a single file for potential secrets."""
        file_path = Path(path)
        if not file_path.exists():
            return []
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        relative = str(file_path)
        if file_path.is_relative_to(self.root):
            relative = str(file_path.relative_to(self.root))
        return self.scan_text(text, relative)

    def scan(self) -> list[SecretFinding]:
        """Scan the project directory for potential secrets."""
        self._findings = []
        if not self.root.exists():
            return self._findings

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            if path.suffix.lower() not in self.extensions and path.name != ".env":
                continue
            self._findings.extend(self.scan_file(path))
        return self._findings

    @property
    def findings(self) -> list[SecretFinding]:
        """Return scan findings, running a scan on first access."""
        if not self._findings and self.root.exists():
            self.scan()
        return list(self._findings)

    def summary(self) -> str:
        """Return a human-readable summary of scan results."""
        findings = self.findings
        if not findings:
            return f"No potential secrets found in {self.root}"

        by_kind: dict[str, int] = {}
        for finding in findings:
            by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1

        lines = [
            f"Secrets scan: {self.root}",
            f"Potential findings: {len(findings)}",
        ]
        for kind, count in sorted(by_kind.items()):
            lines.append(f"  {kind}: {count}")
        return "\n".join(lines)

    def to_context(self, max_findings: int = 50) -> str:
        """Build LLM context from secret scan results."""
        findings = self.findings
        if not findings:
            return self.summary()

        lines = [self.summary(), "", "Findings:"]
        for finding in findings[:max_findings]:
            lines.append(f"  {finding.format()} [{finding.confidence}]")
        if len(findings) > max_findings:
            lines.append(f"  ... and {len(findings) - max_findings} more")
        return "\n".join(lines)
