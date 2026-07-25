"""Tests for chains."""

from unittest.mock import MagicMock

from devai.chains.chain import Chain
from devai.core.models import ChatResponse
from devai.prompts.template import PromptTemplate


def test_chain_run():
  client = MagicMock()
  client.chat.return_value = ChatResponse(content="Review: looks good")
  chain = Chain(
    PromptTemplate("Review this {language} code: {code}"),
    client=client,
  )
  result = chain.run(language="python", code="x=1")
  assert result == "Review: looks good"
  client.chat.assert_called_once()


def test_chain_with_post_process():
  client = MagicMock()
  client.chat.return_value = ChatResponse(content="  trimmed  ")
  chain = Chain(
    "Say {word}",
    client=client,
    post_process=str.strip,
  )
  result = chain.run(word="hello")
  assert result == "trimmed"
