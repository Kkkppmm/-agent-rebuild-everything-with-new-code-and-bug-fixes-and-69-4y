# DevAI

A lightweight Python AI library for developers and programmers. Chat, stream, embed, and run tool-calling agents across **OpenAI**, **Anthropic**, and **Ollama** with one unified API.

## Features

- **Unified API** — switch providers with a single `provider=` argument
- **Async-first** — sync helpers included (`ask_sync`, `chat_sync`)
- **Streaming** — token-by-token responses
- **Tool calling** — register Python functions and run agent loops
- **Embeddings** — OpenAI and Ollama compatible endpoints
- **Prompt utilities** — templates and multi-turn chat builders
- **Typed** — Pydantic models throughout

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
import asyncio
from devai import DevAI, Message, Role

async def main():
    ai = DevAI(provider="openai")  # or anthropic, ollama
    answer = await ai.ask(
        "Write a Python function that checks if a string is a palindrome.",
        system="You are an expert Python developer. Be concise.",
    )
    print(answer)

asyncio.run(main())
```

## Providers

| Provider   | Env key              | Default model              |
|-----------|----------------------|----------------------------|
| `openai`  | `OPENAI_API_KEY`     | `gpt-4o-mini`              |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-5-haiku-latest`  |
| `ollama`  | (none)               | `llama3.2`                 |

Set `DEVAI_PROVIDER` and `DEVAI_MODEL` to override defaults.

## Chat

```python
from devai import DevAI, Message, Role

ai = DevAI()

response = await ai.chat([
    Message(role=Role.SYSTEM, content="You are a code reviewer."),
    Message(role=Role.USER, content="Review: def add(a,b): return a+b"),
])

print(response.content)
print(response.usage.total_tokens)
```

## Streaming

```python
async for chunk in ai.stream([Message(role=Role.USER, content="Count to 5")]):
    if chunk.content:
        print(chunk.content, end="", flush=True)
    if chunk.done:
        break
```

## Tool calling

```python
from devai import DevAI, Message, Role
from devai.tools import ToolRegistry

registry = ToolRegistry()

@registry.tool
def run_python(code: str) -> str:
    """Execute a short Python snippet and return stdout."""
    # your sandbox here
    return "42"

ai = DevAI()
messages = [Message(role=Role.USER, content="What is 6 * 7? Use run_python.")]
result = await ai.run_tools(messages, registry)
print(result.content)
```

## Prompt templates

```python
from devai.prompts import PromptTemplate, ChatPrompt

tpl = PromptTemplate("Refactor this {language} code:\n\n{code}")
messages = tpl.to_messages(language="Python", code="def f(x): return x*2")

prompt = (
    ChatPrompt()
    .system("You are a senior engineer.")
    .user("Explain asyncio in 3 sentences.")
    .build()
)
```

## Embeddings

```python
result = await ai.embed(["hello world", "devai library"])
print(len(result.embeddings[0]))
```

## Sync API

```python
ai = DevAI()
text = ai.ask_sync("Hello!")
```

## License

MIT
