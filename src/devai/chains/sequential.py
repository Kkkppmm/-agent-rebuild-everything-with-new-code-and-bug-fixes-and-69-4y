"""Sequential multi-step chain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from devai.core.client import LLMClient
from devai.core.messages import Message
from devai.prompts.template import PromptTemplate


@dataclass
class ChainStep:
    name: str
    prompt: PromptTemplate
    output_key: str


@dataclass
class SequentialChain:
    """Run multiple prompt steps in sequence, passing outputs forward."""

    client: LLMClient
    steps: list[ChainStep]
    system_message: str | None = None

    def run(self, **initial_inputs: str) -> dict[str, str]:
        context: dict[str, Any] = dict(initial_inputs)
        for step in self.steps:
            prompt_vars = {k: context[k] for k in step.prompt.input_variables if k in context}
            messages: list[Message] = []
            if self.system_message:
                messages.append(Message.system(self.system_message))
            messages.append(Message.user(step.prompt.format(**prompt_vars)))
            response = self.client.complete(messages)
            context[step.output_key] = response.content
        return {step.output_key: context[step.output_key] for step in self.steps}

    async def arun(self, **initial_inputs: str) -> dict[str, str]:
        context: dict[str, Any] = dict(initial_inputs)
        for step in self.steps:
            prompt_vars = {k: context[k] for k in step.prompt.input_variables if k in context}
            messages: list[Message] = []
            if self.system_message:
                messages.append(Message.system(self.system_message))
            messages.append(Message.user(step.prompt.format(**prompt_vars)))
            response = await self.client.acomplete(messages)
            context[step.output_key] = response.content
        return {step.output_key: context[step.output_key] for step in self.steps}
