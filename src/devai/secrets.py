"""SecretsScanner — heuristic detection of hardcoded credentials in source code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecretFinding:
    """A potential hardcoded secret detected in source code."""

    path: str
    lineno: int
    kind: str
    snippet: str
    severity: str = "high"

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "lineno": self.lineno,
            "kind": self.kind,
            "snippet": self.snippet,
            "severity": self.severity,
        }


_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key", r"(?:AKIA[0-9A-Z]{16})", "critical"),
    ("aws_secret_key", r"(?:aws_secret_access_key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"])", "critical"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("github_token", r"(?:ghp_[A-Za-z0-9]{36,})", "critical"),
    ("generic_api_key", r"(?:api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"])", "high"),
    ("password_literal", r"(?:password\s*[=:]\s*['\"][^'\"]{4,}['\"])", "high"),
    ("bearer_token", r"(?:Bearer\s+[A-Za-z0-9_\-\.]{20,})", "high"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "critical"),
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "medium"),
]


@dataclass
class SecretsScanner:
    """Scan a project for heuristic hardcoded credential patterns.

    SecretsScanner flags likely secrets using regex heuristics. It is not a
  substitute for a dedicated secret scanner, but useful for quick pre-commit
  checks in developer workflows.
    """

    root: Path
    _findings: list[SecretFinding] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    def scan(
        self,
        *,
        extensions: frozenset[str] = frozenset({".py", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".toml"}),
        exclude: frozenset[str] = frozenset({"__pycache__", ".git", ".venv", "venv", "node_modules"}),
    ) -> list[SecretFinding]:
        """Scan files and return potential secret findings."""
        self._findings.clear()

        if not self.root.is_dir():
            raise FileNotFoundError(f"Project root not found: {self.root}")

        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in extensions and path.name not in {".env", "credentials"}:
                continue
            if any(part in exclude for part in path.parts):
                continue
            self._scan_file(path)

        return list(self._findings)

    def summary(self) -> dict[str, int | list[dict[str, str | int]]]:
        """Return a summary of findings grouped by severity."""
        if not self._findings:
            self.scan()
        by_severity: dict[str, int] = {}
        for f in self._findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "total": len(self._findings),
            "by_severity": by_severity,
            "findings": [f.to_dict() for f in self._findings],
        }

    def _scan_file(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return

        rel = str(path.relative_to(self.root))
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for kind, pattern, severity in _PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    snippet = line.strip()[:120]
                    self._findings.append(
                        SecretFinding(
                            path=rel,
                            lineno=lineno,
                            kind=kind,
                            snippet=snippet,
                            severity=severity,
                        )
                    )
                    break
