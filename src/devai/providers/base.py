"""Shared HTTP utilities for providers."""

from __future__ import annotations

import json
from typing import Any

import httpx

from devai.exceptions import ProviderError, RateLimitError


def build_client(config, *, headers: dict[str, str] | None = None) -> httpx.AsyncClient:
    merged = dict(config.extra_headers)
    if headers:
        merged.update(headers)
    return httpx.AsyncClient(
        base_url=config.base_url,
        headers=merged,
        timeout=config.timeout,
    )


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    provider: str,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = await client.request(method, path, json=json_body)
    if response.status_code == 429:
        raise RateLimitError(
            f"{provider} rate limit exceeded",
            provider=provider,
            status_code=429,
        )
    if response.status_code >= 400:
        detail = response.text
        try:
            payload = response.json()
            detail = payload.get("error", payload)
            if isinstance(detail, dict):
                detail = detail.get("message", json.dumps(detail))
        except Exception:
            pass
        raise ProviderError(str(detail), provider=provider, status_code=response.status_code)
    return response.json()


def parse_sse_line(line: str) -> dict[str, Any] | None:
    if not line.startswith("data: "):
        return None
    data = line[6:].strip()
    if data == "[DONE]":
        return {"done": True}
    return json.loads(data)
