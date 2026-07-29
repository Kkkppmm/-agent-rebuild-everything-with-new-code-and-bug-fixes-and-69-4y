"""Environment diagnostics for DevAI projects."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.config_file import find_config_file, load_config_file
from devai.health import HealthChecker, MockLLMClient


@dataclass
class DoctorCheck:
    """A single diagnostic check result."""

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
    """Aggregated output from a DevDoctor run."""

    passed: bool
    checks: list[DoctorCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
        }

    def summary(self) -> str:
        """Human-readable summary of all checks."""
        lines = ["DevAI Doctor", "=" * 12]
        for check in self.checks:
            status = "PASS" if check.passed else "FAIL"
            lines.append(f"[{status}] {check.name}: {check.message}")
        lines.append("")
        lines.append("Overall: " + ("healthy" if self.passed else "issues found"))
        return "\n".join(lines)


class DevDoctor:
    """Run environment and configuration diagnostics for DevAI."""

    def __init__(self, project_path: str | Path | None = None) -> None:
        self.project_path = Path(project_path or ".").resolve()

    def run(self, *, check_provider: bool = False, probe: bool = False) -> DoctorResult:
        """Execute all diagnostic checks."""
        checks = [
            self._check_python_version(),
            self._check_devai_installed(),
            self._check_config_file(),
            self._check_api_key(),
            self._check_optional_deps(),
        ]
        if check_provider:
            checks.append(self._check_provider_health(probe=probe))
        passed = all(check.passed for check in checks)
        return DoctorResult(passed=passed, checks=checks)

    def _check_python_version(self) -> DoctorCheck:
        ok = sys.version_info >= (3, 10)
        return DoctorCheck(
            name="python",
            passed=ok,
            message=f"Python {sys.version_info.major}.{sys.version_info.minor}"
            + (" (supported)" if ok else " (requires >= 3.10)"),
        )

    def _check_devai_installed(self) -> DoctorCheck:
        try:
            import devai

            return DoctorCheck(
                name="devai",
                passed=True,
                message=f"devai {devai.__version__} installed",
            )
        except ImportError as exc:
            return DoctorCheck(
                name="devai",
                passed=False,
                message=str(exc),
            )

    def _check_config_file(self) -> DoctorCheck:
        config_path = find_config_file(self.project_path)
        if config_path is None:
            return DoctorCheck(
                name="config",
                passed=True,
                message="No project config found (optional)",
                details={"hint": "Run `devai config-init` to create .devai.yaml"},
            )
        try:
            config = load_config_file(config_path)
            return DoctorCheck(
                name="config",
                passed=True,
                message=f"Found {config_path.name}",
                details={"model": config.model, "path": str(config_path)},
            )
        except Exception as exc:
            return DoctorCheck(
                name="config",
                passed=False,
                message=f"Invalid config at {config_path}: {exc}",
            )

    def _check_api_key(self) -> DoctorCheck:
        keys = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "DEVAI_API_KEY": os.environ.get("DEVAI_API_KEY"),
        }
        found = [name for name, value in keys.items() if value]
        if found:
            return DoctorCheck(
                name="api_key",
                passed=True,
                message=f"Found {', '.join(found)}",
            )
        config_path = find_config_file(self.project_path)
        if config_path:
            try:
                config = load_config_file(config_path)
                if config.api_key:
                    return DoctorCheck(
                        name="api_key",
                        passed=True,
                        message="API key set in project config",
                    )
            except Exception:
                pass
        return DoctorCheck(
            name="api_key",
            passed=True,
            message="No API key in environment (use mock mode or set OPENAI_API_KEY)",
            details={"hint": "Set OPENAI_API_KEY or use --mock"},
        )

    def _check_optional_deps(self) -> DoctorCheck:
        optional = {"yaml": "pyyaml", "openai": "openai"}
        installed: list[str] = []
        missing: list[str] = []
        for feature, module in optional.items():
            if importlib.util.find_spec(module) is not None:
                installed.append(feature)
            else:
                missing.append(feature)
        return DoctorCheck(
            name="optional_deps",
            passed=True,
            message="Optional extras: "
            + (", ".join(installed) if installed else "none")
            + (f" (missing: {', '.join(missing)})" if missing else ""),
            details={"installed": installed, "missing": missing},
        )

    def _check_provider_health(self, *, probe: bool) -> DoctorCheck:
        config_path = find_config_file(self.project_path)
        try:
            if config_path:
                config = load_config_file(config_path)
                if config.api_key == "mock":
                    checker = HealthChecker(client=MockLLMClient())
                else:
                    checker = HealthChecker(config=config)
            else:
                checker = HealthChecker(client=MockLLMClient())
            result = checker.check(probe=probe)
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
                message=str(exc),
            )


def run_doctor(
    project_path: str | Path | None = None,
    *,
    check_provider: bool = False,
    probe: bool = False,
) -> DoctorResult:
    """One-line environment diagnostics."""
    return DevDoctor(project_path).run(check_provider=check_provider, probe=probe)
