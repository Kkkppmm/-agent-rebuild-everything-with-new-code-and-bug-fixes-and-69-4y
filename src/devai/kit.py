"""DevKit — unified developer workspace for DevAI."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.core.client import LLMClientProtocol
from devai.core.config import DevAIConfig
from devai.pipeline import DevPipeline
from devai.presets import get_preset, list_presets
from devai.program import DevProgram, ProgramResult
from devai.project import CodeProject
from devai.tools.code_utils import git_diff


@dataclass
class DevKit:
    """Unified entry point for developer-focused AI workflows.

  Combines CodeAssistant, CodeProject, DevProgram, and DevPipeline
  into a single ergonomic API for day-to-day programming tasks.
    """

    assistant: CodeAssistant
    project_path: str | Path | None = None
    _project: CodeProject | None = field(default=None, init=False, repr=False)

    @classmethod
    def from_config(
        cls,
        config: DevAIConfig | None = None,
        *,
        project_path: str | Path | None = None,
        **kwargs: Any,
    ) -> DevKit:
        """Create a DevKit from configuration."""
        assistant = CodeAssistant(config=config, **kwargs)
        return cls(assistant=assistant, project_path=project_path)

    @classmethod
    def from_client(
        cls,
        client: LLMClientProtocol,
        *,
        project_path: str | Path | None = None,
    ) -> DevKit:
        """Create a DevKit with a custom LLM client."""
        return cls(assistant=CodeAssistant(client=client), project_path=project_path)

    @property
    def project(self) -> CodeProject | None:
        """Lazy-loaded CodeProject for the configured path."""
        if self.project_path is None:
            return None
        if self._project is None:
            self._project = CodeProject(str(self.project_path))
        return self._project

    def pipeline(self) -> DevPipeline:
        """Create a new DevPipeline bound to this kit's assistant."""
        return DevPipeline(self.assistant)

    def program(self, name: str = "program") -> DevProgram:
        """Create a new DevProgram bound to this kit's assistant."""
        return DevProgram(name, self.assistant)

    def preset(self, name: str) -> DevProgram:
        """Load a built-in program preset."""
        return get_preset(name, self.assistant)

    @staticmethod
    def presets() -> list[dict[str, str]]:
        """List available built-in program presets."""
        return list_presets()

    def _read_code(self, code_or_path: str | None = None) -> str:
        if code_or_path is None:
            if self.project_path is None:
                raise ValueError("Provide code or set project_path on DevKit")
            raise ValueError("Provide code or a file path")
        path = Path(code_or_path)
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
        return code_or_path

    def audit(self, code_or_path: str | None = None) -> str:
        """Run a full audit (review + security + docstrings) on code."""
        code = self._read_code(code_or_path)
        return self.pipeline().full_audit().run_and_summarize(code)

    def pre_commit(self, code_or_path: str | None = None) -> str:
        """Run the pre-commit preset program."""
        code = self._read_code(code_or_path)
        return self.preset("pre-commit").run_and_summarize({"code": code})

    def release_check(self, code_or_path: str | None = None) -> str:
        """Run the release checklist preset program."""
        code = self._read_code(code_or_path)
        return self.preset("release").run_and_summarize({"code": code})

    def onboard(self, code_or_path: str | None = None) -> str:
        """Run the onboarding preset to explain and document code."""
        code = self._read_code(code_or_path)
        return self.preset("onboarding").run_and_summarize({"code": code})

    def review_pr(
        self,
        *,
        diff: str | None = None,
        code: str | None = None,
    ) -> str:
        """Review a pull request using the pr-review preset."""
        context: dict[str, str] = {}
        if diff is not None:
            context["diff"] = diff
        else:
            context["diff"] = git_diff()
        if code is not None:
            context["code"] = self._read_code(code)
        elif self.project_path is not None:
            project = self.project
            if project is not None:
                context["code"] = project.build_context()
        if "code" not in context:
            raise ValueError("Provide code or set project_path for PR review")
        return self.preset("pr-review").run_and_summarize(context)

    def ci_gate(
        self,
        *,
        diff: str | None = None,
        code: str | None = None,
    ) -> str:
        """Run the ci-gate preset for CI pipeline checks."""
        context: dict[str, str] = {}
        context["diff"] = diff if diff is not None else git_diff()
        if code is not None:
            context["code"] = self._read_code(code)
        elif self.project_path is not None:
            project = self.project
            if project is not None:
                context["code"] = project.build_context()
        if "code" not in context:
            raise ValueError("Provide code or set project_path for CI gate")
        return self.preset("ci-gate").run_and_summarize(context)

    def review_project(self, query: str | None = None) -> str:
        """Review the configured project directory."""
        if self.project_path is None:
            raise ValueError("Set project_path on DevKit to review a project")
        return self.assistant.review_project(str(self.project_path), query=query)

    def run_program(
        self,
        program: DevProgram | str,
        context: dict[str, str] | None = None,
    ) -> list[ProgramResult]:
        """Run a DevProgram or preset by name."""
        if isinstance(program, str):
            program = self.preset(program)
        return program.run(context or {})

    def summarize(self, results: list[ProgramResult]) -> str:
        """Format program results as markdown."""
        parts = [f"## {r.name} ({r.action})\n\n{r.output}" for r in results]
        return "\n\n---\n\n".join(parts)
