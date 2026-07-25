# DevAI Examples

## Quick chat

```python
from devai import LLMClient, DevAIConfig

client = LLMClient(DevAIConfig(api_key="sk-...", model="gpt-4o-mini"))
answer = client.chat("Explain Python decorators in one paragraph.")
print(answer)
```

## Code review chain

```python
from devai import LLMClient, Chain
from devai.prompts.dev import CODE_REVIEW

client = LLMClient()
chain = Chain(client, CODE_REVIEW)

result = chain.run(
    language="python",
    code="def divide(a, b):\n    return a / b",
)
print(result["result"])
```

## Agent with tools

```python
from devai import LLMClient, Agent, ToolRegistry
from devai.tools.code import explain_code, lint_python

client = LLMClient()
tools = ToolRegistry()

@tools.register(description="Analyze Python code structure")
def analyze(code: str) -> str:
    return explain_code(code)

@tools.register(description="Lint Python code for common issues")
def lint(code: str) -> str:
    import json
    return json.dumps(lint_python(code))

agent = Agent(
    client,
    tools=tools,
    system="You are a Python code assistant. Use tools when helpful.",
)

print(agent.run("Analyze and lint this code: def f(): pass"))
```

## Streaming

```python
from devai import LLMClient
from devai.core.models import Message, Role

client = LLMClient()
messages = [Message(role=Role.USER, content="Write a haiku about coding.")]

for chunk in client.stream(messages):
    print(chunk, end="", flush=True)
```

## Environment configuration

```bash
export DEVAI_API_KEY=sk-...
export DEVAI_MODEL=gpt-4o-mini
export DEVAI_BASE_URL=https://api.openai.com/v1
```

```python
from devai import LLMClient

client = LLMClient()  # loads from DEVAI_* env vars
```
