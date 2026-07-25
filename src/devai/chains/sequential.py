"""Sequential chain for multi-step LLM pipelines."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from devai.chains.chain import Chain
from devai.prompts.template import PromptTemplate


class SequentialChain:
  """Run multiple chains in sequence, passing each output to the next."""

  def __init__(
    self,
    steps: list[Chain | tuple[PromptTemplate | str, str]],
    *,
    input_key: str = "input",
    output_key: str = "output",
  ) -> None:
    self.steps = [self._normalize_step(step) for step in steps]
    self.input_key = input_key
    self.output_key = output_key

  @staticmethod
  def _normalize_step(
    step: Chain | tuple[PromptTemplate | str | Chain, str],
  ) -> tuple[Chain, str]:
    if isinstance(step, Chain):
      return step, "output"
    template, output_key = step
    if isinstance(template, Chain):
      return template, output_key
    return Chain(template), output_key

  def run(self, **variables: Any) -> dict[str, Any]:
    """Execute all steps and return accumulated variables."""
    state = dict(variables)

    for chain, output_key in self.steps:
      result = chain.run(**state)
      state[output_key] = result

    return state

  async def arun(self, **variables: Any) -> dict[str, Any]:
    """Async version of run."""
    state = dict(variables)

    for chain, output_key in self.steps:
      result = await chain.arun(**state)
      state[output_key] = result

    return state

  def pipe(self, post_process: Callable[[dict[str, Any]], Any]) -> Callable[..., Any]:
    """Return a callable that runs the chain and applies a post-processor."""

    def runner(**variables: Any) -> Any:
      return post_process(self.run(**variables))

    return runner
