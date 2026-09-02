"""Safe code execution sandbox for testing generated code."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    """Result from a sandbox execution."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(self.stderr)
        return "\n".join(parts).strip()


class CodeSandbox:
    """Run Python code in an isolated subprocess with timeout."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        python_executable: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.python_executable = python_executable or sys.executable

    def run_python(self, code: str) -> SandboxResult:
        """Execute Python code in a temporary file."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)

        try:
            proc = subprocess.run(
                [self.python_executable, str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return SandboxResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return SandboxResult(
                stdout=stdout,
                stderr=stderr or f"Execution timed out after {self.timeout}s",
                exit_code=-1,
                timed_out=True,
            )
        finally:
            tmp_path.unlink(missing_ok=True)

    def run_tests(self, code: str, test_code: str) -> SandboxResult:
        """Run test code against implementation code."""
        combined = f"{code}\n\n{test_code}"
        return self.run_python(combined)

    def verify_output(self, code: str, expected_in_stdout: str) -> bool:
        """Run code and check that expected text appears in stdout."""
        result = self.run_python(code)
        return result.success and expected_in_stdout in result.stdout
