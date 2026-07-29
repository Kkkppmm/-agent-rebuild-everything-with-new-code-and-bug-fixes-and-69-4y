"""Environment diagnostics for DevAI installations."""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DoctorCheck:
    """Result of a single diagnostic check."""

    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class DoctorResult:
    """Aggregated environment diagnostics."""

    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed_checks(self) -> list[DoctorCheck]:
        return [check for check in self.checks if not check.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checks": [check.to_dict() for check in self.checks],
        }

    def summary(self) -> str:
        """Format diagnostics as human-readable markdown."""
        lines = ["# DevAI Doctor", ""]
        status = "PASS" if self.healthy else "FAIL"
        lines.append(f"**Overall:** {status}")
        lines.append("")
        for check in self.checks:
            icon = "✓" if check.passed else "✗"
            lines.append(f"- {icon} **{check.name}**: {check.message}")
        return "\n".join(lines)


class DevDoctor:
    """Run environment diagnostics for DevAI developers."""

    def __init__(self, project_path: str | Path | None = None) -> None:
        self.project_path = Path(project_path or Path.cwd()).resolve()

    def run(self, *, check_provider: bool = False) -> DoctorResult:
        """Run all diagnostic checks."""
        checks = [
            self._check_python_version(),
            self._check_devai_version(),
            self._check_core_dependencies(),
            self._check_optional_dependencies(),
            self._check_api_keys(),
            self._check_git(),
            self._check_config_file(),
        ]
        if check_provider:
            checks.append(self._check_provider_health())
        return DoctorResult(checks=checks)

    def _check_python_version(self) -> DoctorCheck:
        version = sys.version_info
        ok = version >= (3, 10)
        return DoctorCheck(
            name="python",
            passed=ok,
            message=(
                f"Python {version.major}.{version.minor}.{version.micro}"
                if ok
                else f"Python {version.major}.{version.minor} is too old (need >= 3.10)"
            ),
            details={"platform": platform.platform()},
        )

    def _check_devai_version(self) -> DoctorCheck:
        try:
            from importlib.metadata import version

            ver = version("devai")
        except Exception:
            ver = "unknown"
        return DoctorCheck(
            name="devai",
            passed=True,
            message=f"DevAI {ver} installed",
            details={"version": ver},
        )

    def _check_core_dependencies(self) -> DoctorCheck:
        missing: list[str] = []
        for package in ("httpx", "pydantic"):
            if importlib.util.find_spec(package) is None:
                missing.append(package)
        return DoctorCheck(
            name="dependencies",
            passed=not missing,
            message=(
                "Core dependencies available"
                if not missing
                else f"Missing packages: {', '.join(missing)}"
            ),
            details={"missing": missing},
        )

    def _check_optional_dependencies(self) -> DoctorCheck:
        optional = {
            "yaml": "pyyaml",
            "openai": "openai",
        }
        available: dict[str, bool] = {}
        for label, package in optional.items():
            available[label] = importlib.util.find_spec(package) is not None
        missing = [name for name, installed in available.items() if not installed]
        return DoctorCheck(
            name="optional",
            passed=True,
            message=(
                "All optional packages installed"
                if not missing
                else f"Optional packages not installed: {', '.join(missing)}"
            ),
            details={"available": available, "missing": missing},
        )

    def _check_api_keys(self) -> DoctorCheck:
        keys = {
            "OPENAI_API_KEY": bool(os.environ.get("OPENAI_API_KEY")),
            "ANTHROPIC_API_KEY": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "DEVAI_API_KEY": bool(os.environ.get("DEVAI_API_KEY")),
        }
        has_any = any(keys.values())
        return DoctorCheck(
            name="api_keys",
            passed=True,
            message=(
                "API key found in environment"
                if has_any
                else "No API keys set (use mock mode or set OPENAI_API_KEY)"
            ),
            details=keys,
        )

    def _check_git(self) -> DoctorCheck:
        git_path = shutil.which("git")
        if git_path is None:
            return DoctorCheck(
                name="git",
                passed=False,
                message="git not found on PATH",
            )
        git_dir = self.project_path / ".git"
        return DoctorCheck(
            name="git",
            passed=True,
            message=(
                f"git available ({git_path})"
                + (", repository detected" if git_dir.exists() else ", not a git repo")
            ),
            details={"path": git_path, "is_repo": git_dir.exists()},
        )

    def _check_config_file(self) -> DoctorCheck:
        from devai.config_file import CONFIG_FILENAMES, find_config_file

        found = find_config_file(self.project_path)
        if found:
            return DoctorCheck(
                name="config",
                passed=True,
                message=f"Config file found: {found.name}",
                details={"path": str(found)},
            )
        return DoctorCheck(
            name="config",
            passed=True,
            message=f"No config file (looked for {', '.join(CONFIG_FILENAMES)})",
            details={"searched": list(CONFIG_FILENAMES)},
        )

    def _check_provider_health(self) -> DoctorCheck:
        from devai.health import check_health

        try:
            result = check_health(use_mock=True, probe=True)
            return DoctorCheck(
                name="provider",
                passed=result.healthy,
                message=result.message,
                details=result.to_dict(),
            )
        except Exception as exc:
            return DoctorCheck(
                name="provider",
                passed=False,
                message=f"Health check failed: {exc}",
            )


def run_doctor(
    project_path: str | Path | None = None,
    *,
    check_provider: bool = False,
) -> DoctorResult:
    """Convenience function to run DevAI environment diagnostics."""
    return DevDoctor(project_path=project_path).run(check_provider=check_provider)
