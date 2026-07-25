"""Quick start — no API key required (uses mock provider)."""

from devai import DevAI, PromptTemplate

ai = DevAI.mock()

# One-liner chat
print(ai.chat("Hello, DevAI!").content)

# Echo mode (mock provider)
print(ai.chat("echo: This is echoed back").content)

# Prompt templates
tpl = PromptTemplate("Explain {topic} in {style}.")
prompt = tpl.format(topic="decorators", style="simple terms")
print(ai.chat(prompt).content)

# Streaming
print("Stream:", end=" ")
for token in ai.chat_stream("Hello"):
    print(token, end="", flush=True)
print()
