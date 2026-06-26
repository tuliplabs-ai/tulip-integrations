# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""CrowdStrike Falcon EDR integration — host forensics + containment.

Implements the core ``EndpointSource`` port so it drops into
``SecurityContext(endpoint=CrowdStrikeEndpoint())``. With ``CROWDSTRIKE_URL`` +
``CROWDSTRIKE_TOKEN`` set it queries the Falcon API; with neither set it returns
the bundled, benign offline reference (the core EDR sample) so it runs in CI
with no credentials.

``isolate`` is a **containment write** — gate it through ``ctx.actions`` /
``approve()`` before calling. LIVE PATH: exercised against a mocked HTTP
transport in ``tests/test_live_paths.py`` (request shape + response parsing
verified); CrowdStrike has no free tier, so not run against a real Falcon
instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tulip.security import (
    ToolAdapter,
    as_json,
    env,
    fetch_host_timeline,
    isolate_host,
    list_detections,
)
from tulip.tools import tool


def _base() -> tuple[str | None, str | None]:
    return env("CROWDSTRIKE_URL", "FALCON_URL"), env("CROWDSTRIKE_TOKEN", "FALCON_TOKEN")


def cs_host_timeline(host: str, window: str = "24h") -> dict[str, Any]:
    """Recent process/network/file timeline for a host (Falcon, else offline sample)."""
    url, token = _base()
    if url and token:
        return _cs_get(url, token, f"/devices/entities/devices/v2?ids={host}")
    out = fetch_host_timeline(host, window=window)
    out["source"] = "offline-sample"
    return out


def cs_detections(host: str | None = None) -> dict[str, Any]:
    """Open detections, optionally for one host (Falcon, else offline sample)."""
    url, token = _base()
    if url and token:
        return _cs_get(url, token, "/detects/queries/detects/v1")
    out = list_detections(host)
    out["source"] = "offline-sample"
    return out


def cs_isolate(host_id: str) -> dict[str, Any]:
    """Network-contain a host. A WRITE — approve() it first. (Offline: simulated.)"""
    url, token = _base()
    if url and token:
        return _cs_post(
            url, token, "/devices/entities/devices-actions/v2?action_name=contain", host_id
        )
    out = isolate_host(host_id)
    out["source"] = "offline-sample"
    return out


def _cs_get(url: str, token: str, path: str) -> dict[str, Any]:
    import httpx

    with httpx.Client(
        base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as c:
        resp = c.get(path)
        resp.raise_for_status()
        return {"source": "crowdstrike", "data": resp.json()}


def _cs_post(url: str, token: str, path: str, host_id: str) -> dict[str, Any]:
    import httpx

    with httpx.Client(
        base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as c:
        resp = c.post(path, json={"ids": [host_id]})
        resp.raise_for_status()
        return {"source": "crowdstrike", "host_id": host_id, "contained": True}


@tool(
    name="cs_host_timeline", description="Pull a host's recent EDR timeline from CrowdStrike Falcon"
)
async def cs_host_tool(host: str, window: str = "24h") -> str:
    return as_json(cs_host_timeline(host, window=window))


@tool(
    name="cs_detections",
    description="List open CrowdStrike Falcon detections, optionally for one host",
)
async def cs_detections_tool(host: str = "") -> str:
    return as_json(cs_detections(host or None))


@tool(
    name="cs_isolate",
    description="Network-contain a host via CrowdStrike Falcon (a write)",
    idempotent=True,
)
async def cs_isolate_tool(host_id: str) -> str:
    return as_json(cs_isolate(host_id))


@dataclass(frozen=True)
class CrowdStrikeEndpoint:
    """A :class:`~tulip.security.SecurityContext` ``EndpointSource`` via Falcon."""

    async def get_host(self, host: str, *, window: str = "24h") -> dict[str, Any]:
        return cs_host_timeline(host, window=window)

    async def detections(self, host: str | None = None) -> dict[str, Any]:
        return cs_detections(host)

    async def isolate(self, host_id: str) -> dict[str, Any]:
        return cs_isolate(host_id)


def crowdstrike_adapter() -> ToolAdapter:
    return ToolAdapter(
        name="crowdstrike",
        vendor="CrowdStrike Falcon EDR",
        _tools=[cs_host_tool, cs_detections_tool, cs_isolate_tool],
    )


__all__ = [
    "CrowdStrikeEndpoint",
    "crowdstrike_adapter",
    "cs_detections",
    "cs_detections_tool",
    "cs_host_timeline",
    "cs_host_tool",
    "cs_isolate",
    "cs_isolate_tool",
]
