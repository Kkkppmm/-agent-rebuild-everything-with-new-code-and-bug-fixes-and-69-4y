"""Environment diagnostics for DevAI."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from devai.config_file import find_config_file

_DEVAI_VERSION = importlib.metadata.version("devai")


@dataclass
class DoctorCheck:
    """A single diagnostic check result."""

    name: str
    status: str  # ok, warn, error
    message: str


@dataclass
class DoctorResult:
    """Complete environment diagnostic report."""

    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not any(check.status == "error" for check in self.checks)

    def format_report(self) -> str:
        lines = [f"DevAI Doctor v{_DEVAI_VERSION}", ""]
        for check in self.checks:
            icon = {"ok": "✓", "warn": "!", "error": "✗"}.get(check.status, "?")
            lines.append(f"[{icon}] {check.name}: {check.message}")
        lines.append("")
        lines.append("Overall: " + ("healthy" if self.healthy else "issues found"))
        return "\n".join(lines)


class DevDoctor:
    """Run environment diagnostics for DevAI."""

    def run(self, *, project_path: str | Path | None = None) -> DoctorResult:
        checks: list[DoctorCheck] = []
        checks.append(self._check_python_version())
        checks.append(self._check_devai_version())
        checks.append(self._check_api_key())
        checks.append(self._check_optional_deps())
        checks.append(self._check_git())
        checks.append(self._check_config_file(project_path))
        return DoctorResult(checks=checks)

    def _check_python_version(self) -> DoctorCheck:
        version = sys.version_info
        if version >= (3, 10):
            return DoctorCheck(
                "python",
                "ok",
                f"Python {version.major}.{version.minor}.{version.micro}",
            )
        return DoctorCheck(
            "python",
            "error",
            f"Python 3.10+ required (found {version.major}.{version.minor})",
        )

    def _check_devai_version(self) -> DoctorCheck:
        return DoctorCheck("devai", "ok", f"DevAI {_DEVAI_VERSION} installed")

    def _check_api_key(self) -> DoctorCheck:
        key = os.environ.get("DEVAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if key:
            return DoctorCheck("api_key", "ok", "API key found in environment")
        return DoctorCheck(
            "api_key",
            "warn",
            "No API key set (use DEVAI_API_KEY or --mock)",
        )

    def _check_optional_deps(self) -> DoctorCheck:
        missing: list[str] = []
        for name, module in [("pyyaml", "yaml"), ("openai", "openai")]:
            if importlib.util.find_spec(module) is None:
                missing.append(name)
        if not missing:
            return DoctorCheck("optional_deps", "ok", "All optional dependencies available")
        return DoctorCheck(
            "optional_deps",
            "warn",
            f"Optional packages not installed: {', '.join(missing)}",
        )

    def _check_git(self) -> DoctorCheck:
        if shutil.which("git"):
            return DoctorCheck("git", "ok", "git CLI available")
        return DoctorCheck("git", "warn", "git not found (git-aware features limited)")

    def _check_config_file(self, project_path: str | Path | None) -> DoctorCheck:
        start = Path(project_path) if project_path else Path.cwd()
        config_path = find_config_file(start)
        if config_path:
            return DoctorCheck("config_file", "ok", f"Found {config_path}")
        return DoctorCheck(
            "config_file",
            "warn",
            "No .devai.yaml/.devai.json config file found",
        )


def run_doctor(project_path: str | Path | None = None) -> DoctorResult:
    """Run environment diagnostics and return the result."""
    return DevDoctor().run(project_path=project_path)
