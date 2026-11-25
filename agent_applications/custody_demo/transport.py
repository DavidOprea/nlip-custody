"""HTTP transport helper shared by the demo's agents and runner."""

from __future__ import annotations

import asyncio

import httpx

from nlip_sdk import NLIPClient, NLIPMessage


def reuse_connections(client: NLIPClient) -> NLIPClient:
    """Give an NLIPClient one pooled ``httpx.AsyncClient`` per event loop.

    The SDK's ``_post`` builds a new ``AsyncClient`` per request, which costs
    0.25-0.35 s on Windows (CA bundle load) and would swamp per-hop latency.
    """
    pools: dict[int, httpx.AsyncClient] = {}

    async def post(destination: str, message: NLIPMessage) -> httpx.Response:
        loop = id(asyncio.get_running_loop())
        if loop not in pools:
            pools[loop] = httpx.AsyncClient(timeout=client.timeout)
        return await pools[loop].post(client.endpoints[destination], json=message.to_dict())

    client._post = post  # type: ignore[method-assign]
    return client
