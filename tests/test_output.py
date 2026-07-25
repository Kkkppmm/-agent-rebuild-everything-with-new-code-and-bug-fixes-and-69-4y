"""Tests for structured output parsing."""

import pytest
from pydantic import BaseModel

from devai.core.exceptions import ParseError
from devai.output.parsers import StructuredParser, parse_json, parse_model
from devai.chains.structured import StructuredChain
from devai.core.config import DevAIConfig
from unittest.mock import AsyncMock, MagicMock


class ReviewIssue(BaseModel):
    severity: str
    description: str


class ReviewResult(BaseModel):
    summary: str
    issues: list[ReviewIssue]


class TestParsers:
    def test_parse_json_from_markdown(self):
        text = 'Here is the result:\n```json\n{"key": "value"}\n```'
        data = parse_json(text)
        assert data == {"key": "value"}

    def test_parse_json_raises_on_missing(self):
        with pytest.raises(ParseError, match="No JSON"):
            parse_json("no json here")

    def test_parse_model(self):
        text = '{"summary": "ok", "issues": [{"severity": "low", "description": "minor"}]}'
        result = parse_model(text, ReviewResult)
        assert result.summary == "ok"
        assert len(result.issues) == 1

    def test_parse_model_validation_error(self):
        with pytest.raises(ParseError, match="Validation failed"):
            parse_model('{"summary": 123}', ReviewResult)

    def test_structured_parser(self):
        parser = StructuredParser(ReviewResult)
        text = '{"summary": "fine", "issues": []}'
        result = parser.parse(text)
        assert result.summary == "fine"


class TestStructuredChain:
    @pytest.mark.asyncio
    async def test_structured_chain(self):
        config = DevAIConfig(api_key="test-key")
        chain = StructuredChain(
            "Review: {code}",
            output_model=ReviewResult,
            config=config,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": '{"summary": "looks good", "issues": []}',
                },
                "finish_reason": "stop",
            }],
        }
        chain.client._client.post = AsyncMock(return_value=mock_resp)

        result = await chain.run(code="def foo(): pass")
        assert isinstance(result, ReviewResult)
        assert result.summary == "looks good"
        await chain.close()
