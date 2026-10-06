"""Optional live threat-intelligence enrichment via the Tavily Search API.

Design contract (matches the pipeline failure philosophy):
- ``TAVILY_API_KEY`` is optional. Without it the client is OFFLINE and callers
  proceed with the local corpus only; nothing blocks and nothing is faked.
- Any HTTP, transport, or payload failure degrades to an empty result set and
  a truthful ``last_status`` string; it never raises into the scan pipeline.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

_TAVILY_ENDPOINT = "https://api.tavily.com/search"
_SNIPPET_LIMIT = 400


@dataclass(frozen=True, slots=True)
class LiveIntelResult:
    """One bounded live-intelligence hit from Tavily."""

    query: str
    title: str
    url: str
    snippet: str
    cwe: str = field(default="")


class TavilyIntelClient:
    """Bounded, failure-tolerant Tavily search client for live threat intel."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = 8.0,
        max_queries: int = 3,
        max_results: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = (api_key or "").strip()
        self._timeout = timeout
        self._transport = transport
        self.max_queries = max(1, int(max_queries))
        self.max_results = max(1, int(max_results))
        self.last_status = "armed" if self.available else "offline"

    @classmethod
    def from_env(
        cls,
        *,
        timeout: float = 8.0,
        max_queries: int = 3,
        max_results: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> "TavilyIntelClient":
        return cls(
            os.environ.get("TAVILY_API_KEY"),
            timeout=timeout,
            max_queries=max_queries,
            max_results=max_results,
            transport=transport,
        )

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def search(self, query: str, *, cwe: str = "") -> list[LiveIntelResult]:
        """Run one Tavily search; any failure degrades to an empty list."""
        if not self.available:
            self.last_status = "offline"
            return []
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                response = await client.post(
                    _TAVILY_ENDPOINT,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={
                        "query": query,
                        "search_depth": "basic",
                        "max_results": self.max_results,
                    },
                )
                response.raise_for_status()
                payload = response.json()
            results: list[LiveIntelResult] = []
            for item in payload.get("results", [])[: self.max_results]:
                title = str(item.get("title") or "untitled")
                url = str(item.get("url") or "")
                snippet = str(item.get("content") or "")[:_SNIPPET_LIMIT]
                if url:
                    results.append(
                        LiveIntelResult(query=query, title=title, url=url, snippet=snippet, cwe=cwe)
                    )
            self.last_status = f"ok ({len(results)} result(s))"
            return results
        except Exception as exc:  # noqa: BLE001 — intel failure ≠ mission failure
            self.last_status = f"error ({type(exc).__name__})"
            logger.warning("Tavily live-intel query failed: %s", exc)
            return []

    async def fetch_for_cwes(
        self, cwes: list[tuple[str, str]]
    ) -> list[LiveIntelResult]:
        """Query live intel for up to ``max_queries`` (cwe, title) pairs."""
        if not self.available:
            self.last_status = "offline"
            return []
        results: list[LiveIntelResult] = []
        for cwe, title in list(cwes)[: self.max_queries]:
            query = f"{cwe} {title} vulnerability advisory exploit writeup"
            results.extend(await self.search(query, cwe=cwe))
        return results


async def enrich_retrieved_intel(
    retrieved: list,
    tavily: TavilyIntelClient | None,
) -> list:
    """Append live-intel documents (same CWEs, live sources) to ``retrieved``.

    A missing/offline/failing client returns the original list untouched, so
    the scan proceeds on the local corpus exactly as before.
    """

    if tavily is None or not tavily.available or not retrieved:
        return retrieved
    live = await tavily.fetch_for_cwes([(item.cwe, item.title) for item in retrieved])
    if not live:
        return retrieved
    fallback_cwe = retrieved[0].cwe
    enriched = list(retrieved)
    for result in live[:6]:
        enriched.append(
            type(retrieved[0])(
                cwe=result.cwe or fallback_cwe,
                title=f"Live Intel: {result.title}",
                keywords=(),
                summary=f"{result.snippet} (source: {result.url})",
                verification="Cross-check the live source before relying on this intel.",
                asi_code="ASI99",
            )
        )
    return enriched


__all__ = ["LiveIntelResult", "TavilyIntelClient", "enrich_retrieved_intel"]
