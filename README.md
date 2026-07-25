# DevAI

A lightweight Python AI library for developers and programs. Chat, stream, embed, define tools, and run agents — with a unified API across OpenAI, Anthropic, and Ollama.

## Features

- **Unified client** — one `DevAI` class for multiple providers
- **Chat & streaming** — sync-style async API with token streaming
- **Embeddings** — generate vectors with similarity helpers
- **Tools** — register Python functions as LLM tools with decorators
- **Agents** — automatic tool-calling loop until a final answer
- **Memory** — buffer and sliding-window conversation memory
- **Prompts** — simple template formatting

## Installation

```bash
pip install devai
```

Or from source:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
import asyncio
from devai import DevAI

async def main():
    client = DevAI(provider="openai", api_key="sk-...")
    response = await client.chat("Explain Python in one sentence.")
    print(response.content)

asyncio.run(main())
```

Set `DEVAI_API_KEY` or `OPENAI_API_KEY` to avoid passing the key explicitly.

## Providers

| Provider   | `provider=`   | Notes                          |
|------------|---------------|--------------------------------|
| OpenAI     | `"openai"`    | Also works with compatible APIs |
| Anthropic  | `"anthropic"` | Claude models                  |
| Ollama     | `"ollama"`    | Local models, no API key       |

```python
# Local Ollama
client = DevAI(provider="ollama", model="llama3.2")

# Anthropic
client = DevAI(provider="anthropic", api_key="sk-ant-...", model="claude-3-5-sonnet-20241022")

# Custom OpenAI-compatible endpoint
client = DevAI(provider="openai", api_key="key", base_url="https://my-gateway/v1")
```

## Streaming

```python
async for chunk in client.stream("Write a haiku about code."):
    if chunk.content:
        print(chunk.content, end="", flush=True)
```

## Chat Sessions

```python
from devai import DevAI, ChatSession

client = DevAI(provider="openai", api_key="sk-...")
session = ChatSession(client, system="You are a concise coding tutor.")

await session.send("What is a list comprehension?")
reply = await session.send("Show me an example with filtering.")
print(reply.content)
```

## Tools

```python
from devai import DevAI, Agent, ToolRegistry

registry = ToolRegistry()

@registry.tool(description="Get weather for a city")
def get_weather(city: str) -> str:
    return f"Sunny in {city}"

client = DevAI(provider="openai", api_key="sk-...")
agent = Agent(client, tools=registry, system="Use tools when needed.")

result = await agent.run("What's the weather in Tokyo?")
print(result.response.content)
```

## Embeddings

```python
from devai import DevAI, Embedder

client = DevAI(provider="openai", api_key="sk-...")
embedder = Embedder(client)

similarity = await embedder.similarity("machine learning", "deep learning")
print(f"Similarity: {similarity:.3f}")

top = await embedder.most_similar(
    "python programming",
    ["java development", "python tutorial", "cooking recipes"],
    top_k=2,
)
for text, score in top:
    print(f"{score:.3f} — {text}")
```

## Prompt Templates

```python
from devai import PromptTemplate

template = PromptTemplate("Summarize {topic} for a {audience}.")
prompt = template.format(topic="neural networks", audience="beginner")
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
