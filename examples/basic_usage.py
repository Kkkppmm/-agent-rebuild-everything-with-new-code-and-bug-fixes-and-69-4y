"""Basic usage examples for DevAI."""

import asyncio

from devai import DevAI, Message, Role
from devai.prompts import ChatPrompt, PromptTemplate
from devai.tools import ToolRegistry


async def quick_ask():
    ai = DevAI(provider="ollama")
    answer = await ai.ask("What is a Python list comprehension?")
    print(answer)


async def chat_with_history():
    ai = DevAI()
    prompt = (
        ChatPrompt()
        .system("You are a helpful programming tutor.")
        .user("What is a decorator in Python?")
        .build()
    )
    response = await ai.chat(prompt)
    print(response.content)


async def with_tools():
    registry = ToolRegistry()

    @registry.tool
    def grep_repo(pattern: str) -> str:
        """Search the codebase for a regex pattern."""
        return f"Found 3 matches for '{pattern}'"

    ai = DevAI()
    result = await ai.run_tools(
        [Message(role=Role.USER, content="Find uses of 'async def' in the repo.")],
        registry,
    )
    print(result.content)


async def with_template():
    tpl = PromptTemplate("Explain {topic} for a {level} developer.")
    messages = tpl.to_messages(topic="generators", level="junior")
    ai = DevAI()
    print((await ai.chat(messages)).content)


if __name__ == "__main__":
    asyncio.run(quick_ask())
