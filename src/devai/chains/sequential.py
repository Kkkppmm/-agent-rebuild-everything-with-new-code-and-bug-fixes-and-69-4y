"""Sequential chain that pipes outputs through multiple steps."""

from typing import Any

from devai.chains.chain import Chain
from devai.prompts.template import PromptTemplate


class SequentialChain:
    """Run multiple chains in sequence, passing output as input to the next."""

    def __init__(self, chains: list[Chain], output_key: str = "output") -> None:
        self.chains = chains
        self.output_key = output_key

    def run(self, **kwargs: Any) -> dict[str, str]:
        results: dict[str, str] = {}
        current_input = dict(kwargs)

        for i, chain in enumerate(self.chains):
            output = chain.run(**current_input)
            key = chain.template.name or f"step_{i}"
            results[key] = output
            current_input[self.output_key] = output

        return results
