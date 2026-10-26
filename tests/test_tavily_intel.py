"""Tests for the optional Tavily live threat-intel enrichment."""

from __future__ import annotations

import json

import httpx
import pytest

from engine.agents.threat_intel_rag import ThreatIntelDocument
from engine.services.tavily_intel import (
    LiveIntelResult,
    TavilyIntelClient,
    enrich_retrieved_intel,
)


def _tavily_payload(count: int = 2) -> dict:
    return {
        "results": [
            {
                "title": f"Advisory {i}",
                "url": f"https://advisories.example/{i}",
                "content": f"Live details for advisory {i}: active exploitation observed.",
            }
            for i in range(count)
        ]
    }


def _armed_client(handler, **kwargs) -> TavilyIntelClient:
    return TavilyIntelClient(
        "tvly-test-key",
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_client_offline_without_key(monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    client = TavilyIntelClient.from_env()
    assert client.available is False
    assert client.last_status == "offline"
    assert await client.search("anything") == []
    assert await client.fetch_for_cwes([("CWE-89", "SQL Injection")]) == []
    assert client.last_status == "offline"


@pytest.mark.asyncio
async def test_search_parses_results_and_sends_bearer():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=_tavily_payload(2))

    client = _armed_client(handler)
    results = await client.search("CWE-89 SQL Injection advisories")
    assert seen["auth"] == "Bearer tvly-test-key"
    assert seen["body"]["query"] == "CWE-89 SQL Injection advisories"
    assert len(results) == 2
    assert all(isinstance(r, LiveIntelResult) for r in results)
    assert results[0].url == "https://advisories.example/0"
    assert "active exploitation" in results[0].snippet
    assert client.last_status == "ok (2 result(s))"


@pytest.mark.asyncio
async def test_search_degrades_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    client = _armed_client(handler)
    assert await client.search("query") == []
    assert client.last_status.startswith("error (")


@pytest.mark.asyncio
async def test_search_degrades_on_transport_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    client = _armed_client(handler)
    assert await client.search("query") == []
    assert client.last_status == "error (ConnectError)"


@pytest.mark.asyncio
async def test_fetch_for_cwes_bounds_queries_and_tags_cwe():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body["query"])
        return httpx.Response(200, json=_tavily_payload(1))

    client = _armed_client(handler, max_queries=2, max_results=3)
    cwes = [("CWE-89", "SQL Injection"), ("CWE-798", "Hard-coded Credentials"),
            ("CWE-862", "Missing Authorization"), ("CWE-20", "Input Validation")]
    results = await client.fetch_for_cwes(cwes)
    assert len(calls) == 2  # max_queries caps the credit spend
    assert calls[0].startswith("CWE-89")
    assert all(r.cwe in {"CWE-89", "CWE-798"} for r in results)


@pytest.mark.asyncio
async def test_enrich_offline_returns_unchanged():
    retrieved = [_KNOWLEDGE_DOC]
    assert await enrich_retrieved_intel(retrieved, None) is retrieved
    offline = TavilyIntelClient(None)
    assert await enrich_retrieved_intel(retrieved, offline) is retrieved


@pytest.mark.asyncio
async def test_enrich_appends_live_docs_with_same_cwe():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_tavily_payload(2))

    client = _armed_client(handler)
    retrieved = [_KNOWLEDGE_DOC]
    enriched = await enrich_retrieved_intel(retrieved, client)
    assert len(enriched) == 3  # 1 local + 2 live
    live = [doc for doc in enriched if doc.title.startswith("Live Intel:")]
    assert len(live) == 2
    assert all(doc.cwe == "CWE-89" for doc in live)  # same CWE → report validation still binds
    assert all("source: https://advisories.example/" in doc.summary for doc in live)
    assert enriched[0] is _KNOWLEDGE_DOC  # local corpus untouched, live appended


@pytest.mark.asyncio
async def test_enrich_caps_live_docs_at_six():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_tavily_payload(3))

    client = _armed_client(handler, max_queries=3, max_results=3)
    retrieved = [_KNOWLEDGE_DOC]
    enriched = await enrich_retrieved_intel(retrieved, client)
    live = [doc for doc in enriched if doc.title.startswith("Live Intel:")]
    assert len(live) <= 6


_KNOWLEDGE_DOC = ThreatIntelDocument(
    cwe="CWE-89",
    title="SQL Injection",
    keywords=("sql",),
    summary="Request values must not be concatenated into SQL.",
    verification="Recommend parameterization.",
)
