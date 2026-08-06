"""InsecureStorageSettingsAnalyzer — detect insecure file/storage configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "storage.py",
    }
)
_FILESYSTEM_STORAGE_RE = re.compile(
    r"(django\.core\.files\.storage\.)?FileSystemStorage",
    re.IGNORECASE,
)
_PUBLIC_S3_ACL_RE = re.compile(
    r"(default_acl|AWS_DEFAULT_ACL|ACL)\s*[=:]\s*['\"]public-read",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(
    r"AWS_ACCESS_KEY_ID\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_AWS_SECRET_KEY_RE = re.compile(
    r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "your-access-key",
        "your-secret-key",
        "xxx",
        "placeholder",
        "test",
        "dummy",
    }
)


@dataclass
class InsecureStorageSettingsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureStorageSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_filesystem_storage(value: str) -> bool:
    return bool(_FILESYSTEM_STORAGE_RE.search(value))


def _is_public_s3_acl(value: str) -> bool:
    lowered = value.lower()
    return lowered in {"public-read", "public-read-write", "authenticated-read"}


def _is_hardcoded_credential(value: str) -> bool:
    if not value or value.startswith("${") or value.startswith("os.environ"):
        return False
    return value.lower() not in _PLACEHOLDER_VALUES and len(value) >= 8


class _InsecureStorageSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureStorageSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureStorageSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            value = _dict_string_value(node.value)
            if name == "DEFAULT_FILE_STORAGE" and value:
                if _is_filesystem_storage(value) and self.filename in _PROD_FILENAMES:
                    self._add(
                        node.lineno,
                        "filesystem_storage_in_production",
                        "high",
                        "FileSystemStorage is not suitable for production — use S3 or object storage",
                        setting=name,
                    )
            if name in {"AWS_DEFAULT_ACL", "AWS_S3_DEFAULT_ACL"} and value:
                if _is_public_s3_acl(value) and self.filename in _PROD_FILENAMES:
                    self._add(
                        node.lineno,
                        "public_s3_acl",
                        "high",
                        "S3 default ACL allows public access — use private ACLs and bucket policies",
                        setting=name,
                    )
            if name == "AWS_ACCESS_KEY_ID" and value:
                if _is_hardcoded_credential(value):
                    self._add(
                        node.lineno,
                        "hardcoded_aws_access_key",
                        "high",
                        "Hardcoded AWS_ACCESS_KEY_ID — load credentials from environment or IAM roles",
                        setting=name,
                    )
            if name == "AWS_SECRET_ACCESS_KEY" and value:
                if _is_hardcoded_credential(value):
                    self._add(
                        node.lineno,
                        "hardcoded_aws_secret_key",
                        "high",
                        "Hardcoded AWS_SECRET_ACCESS_KEY — load credentials from environment or IAM roles",
                        setting=name,
                    )
            if name == "STORAGES" and isinstance(node.value, ast.Dict):
                self._scan_storages_dict(node.value)
        self.generic_visit(node)

    def _scan_storages_dict(self, node: ast.Dict) -> None:
        if self.filename not in _PROD_FILENAMES:
            return
        for storage_key, storage_config in zip(node.keys, node.values):
            if not isinstance(storage_config, ast.Dict):
                continue
            storage_name = _dict_string_value(storage_key) if storage_key else "default"
            if storage_name is None and isinstance(storage_key, ast.Constant):
                storage_name = str(storage_key.value)
            storage_name = storage_name or "default"

            for key_node, value_node in zip(storage_config.keys, storage_config.values):
                key = _dict_string_value(key_node) if key_node else None
                if key is None:
                    continue
                value = _dict_string_value(value_node)
                if key.upper() == "BACKEND" and value and _is_filesystem_storage(value):
                    self._add(
                        storage_config.lineno,
                        "filesystem_storage_in_production",
                        "high",
                        "FileSystemStorage is not suitable for production — use S3 or object storage",
                        setting=f"STORAGES['{storage_name}'].BACKEND",
                    )
                if key.lower() in {"default_acl", "acl"} and value and _is_public_s3_acl(value):
                    self._add(
                        storage_config.lineno,
                        "public_s3_acl",
                        "high",
                        "S3 default ACL allows public access — use private ACLs and bucket policies",
                        setting=f"STORAGES['{storage_name}'].{key}",
                    )


class InsecureStorageSettingsAnalyzer:
    """Detect insecure file and object storage configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureStorageSettingsFinding] = []
        self._stats: InsecureStorageSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureStorageSettingsFinding]:
        findings: list[InsecureStorageSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureStorageSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _FILESYSTEM_STORAGE_RE.search(line) and (
                "DEFAULT_FILE_STORAGE" in line or "BACKEND" in line
            ):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="filesystem_storage_in_production",
                        severity="high",
                        message="FileSystemStorage is not suitable for production — use S3 or object storage",
                        setting="DEFAULT_FILE_STORAGE",
                    )
                )
            if _PUBLIC_S3_ACL_RE.search(line):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="public_s3_acl",
                        severity="high",
                        message="S3 default ACL allows public access — use private ACLs and bucket policies",
                        setting="AWS_DEFAULT_ACL",
                    )
                )
            if _AWS_ACCESS_KEY_RE.search(line):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_aws_access_key",
                        severity="high",
                        message="Hardcoded AWS_ACCESS_KEY_ID — load credentials from environment or IAM roles",
                        setting="AWS_ACCESS_KEY_ID",
                    )
                )
            if _AWS_SECRET_KEY_RE.search(line):
                findings.append(
                    InsecureStorageSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_aws_secret_key",
                        severity="high",
                        message="Hardcoded AWS_SECRET_ACCESS_KEY — load credentials from environment or IAM roles",
                        setting="AWS_SECRET_ACCESS_KEY",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureStorageSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureStorageSettingsFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source, path.name)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureStorageSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureStorageSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure storage settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure storage settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure storage configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
