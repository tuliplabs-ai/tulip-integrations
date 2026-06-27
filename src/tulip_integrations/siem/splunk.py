# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Splunk / Elastic SIEM integration — the reference `tulip-integrations` adapter.

This is the proving template for the integration model: a vendor adapter that
lives **outside** the core SDK, depends on it one-way, implements the core
:class:`~tulip.security.SecurityAdapter` contract, and reuses the core toolkit
(``env`` / ``as_json``) + grounding. It is discovered by **explicit import**
(the community-package model) and wired in via ``security_toolset(extra=...)``::

    from tulip.security import security_toolset
    from tulip_integrations.siem.splunk import splunk_siem_tool

    tools = security_toolset(siem=False, extra=[splunk_siem_tool])

With ``SPLUNK_URL`` + ``SPLUNK_TOKEN`` set it runs an export search against a
Splunk/Elastic-shaped endpoint; with neither set it returns a deterministic,
benign offline sample (RFC 5737 / RFC 1918 docs ranges) so it runs in CI with
no credentials.

LIVE PATH: exercised against a mocked HTTP transport in
``tests/test_live_paths.py`` (request shape + response parsing verified); not
yet run against a real Splunk instance — adjust the path/fields per deployment.
"""

from __future__ import annotations

from dataclasses import dataclass

from tulip.security import ToolAdapter, as_json, env
from tulip.tools import tool

# Benign, invented offline events — Splunk ``_raw``/``sourcetype`` shape.
_OFFLINE_EVENTS: list[dict[str, object]] = [
    {
        "_time": "2026-06-11T09:14:02Z",
        "host": "WS-0142",
        "sourcetype": "WinEventLog:Security",
        "_raw": "winword.exe spawned powershell.exe -enc <base64>",
        "severity": "high",
    },
    {
        "_time": "2026-06-11T09:14:05Z",
        "host": "WS-0142",
        "sourcetype": "Network:Traffic",
        "_raw": "powershell.exe -> 198.51.100.23:443",
        "severity": "high",
    },
    {
        "_time": "2026-06-11T09:11:40Z",
        "host": "WS-0142",
        "sourcetype": "WinEventLog:Security",
        "_raw": "4 failed logons for user svc-backup from 192.0.2.44",
        "severity": "medium",
    },
]


def splunk_search(spl: str, earliest: str = "-24h", count: int = 50) -> dict[str, object]:
    """Run an SPL search against Splunk; offline sample when no credentials.

    Live path (``SPLUNK_URL`` + ``SPLUNK_TOKEN``) POSTs to the export endpoint;
    offline path substring-filters the benign sample events. Same return shape
    either way so an agent's downstream reasoning doesn't change.
    """
    url = env("SPLUNK_URL")
    token = env("SPLUNK_TOKEN")
    if url and token:
        return _splunk_live(url, token, spl, earliest, count)
    needle = spl.lower()
    matched = [e for e in _OFFLINE_EVENTS if needle in as_json(e).lower() or needle in ("", "*")]
    return {
        "spl": spl,
        "earliest": earliest,
        "source": "offline-sample",
        "count": len(matched[:count]),
        "events": matched[:count],
    }


def _splunk_live(url: str, token: str, spl: str, earliest: str, count: int) -> dict[str, object]:
    """POST a search to a Splunk export endpoint (documented shape)."""
    import httpx

    with httpx.Client(
        base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as client:
        resp = client.post(
            "/services/search/jobs/export",
            data={"search": spl, "earliest_time": earliest, "output_mode": "json", "count": count},
        )
        resp.raise_for_status()
        events = resp.json().get("results", [])
    return {
        "spl": spl,
        "earliest": earliest,
        "source": "splunk",
        "count": len(events),
        "events": events[:count],
    }


@tool(name="splunk_search", description="Search Splunk/Elastic SIEM with an SPL query")
async def splunk_siem_tool(spl: str, earliest: str = "-24h") -> str:
    """Tool wrapper: returns matching events as a JSON string."""
    return as_json(splunk_search(spl, earliest=earliest))


def splunk_adapter() -> ToolAdapter:
    """The :class:`~tulip.security.SecurityAdapter` for this integration."""
    return ToolAdapter(name="splunk", vendor="Splunk / Elastic SIEM", _tools=[splunk_siem_tool])


@dataclass(frozen=True)
class SplunkLogs:
    """A :class:`~tulip.security.SecurityContext` ``LogSource`` backed by Splunk.

    Plug it into the domain facade so investigation code stays vendor-agnostic::

        from tulip.security import SecurityContext
        from tulip_integrations.siem.splunk import SplunkLogs

        ctx = SecurityContext(logs=SplunkLogs())
        await ctx.logs.search("failed login spike", window="6h")
    """

    async def search(self, query: str, *, window: str = "24h") -> dict[str, object]:
        return splunk_search(query, earliest=f"-{window}")


__all__ = ["SplunkLogs", "splunk_adapter", "splunk_search", "splunk_siem_tool"]


if __name__ == "__main__":
    print(as_json(splunk_search("powershell", earliest="-6h")))
