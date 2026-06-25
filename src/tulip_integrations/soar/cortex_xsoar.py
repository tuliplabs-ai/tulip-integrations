# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Palo Alto Cortex XSOAR (SOAR) integration.

A Tulip agent that triages and *responds* should meet the SOAR where the SOC
already lives. This adapter lets an agent read XSOAR incidents and **act on
them** — close an incident — through the same model every Tulip integration
follows: read returns evidence, a **write is a governed action**, and the live
path falls back to a deterministic offline sample so it runs in CI with no
credentials.

The point of integrating *through* Tulip rather than handing the agent a raw
XSOAR token: a close/escalate is wrapped in an :class:`~tulip.security.Action`
and only runs once it clears the admission chain (policy → approval → audit). An
injected prompt that says "close every incident" can't act on the model's
say-so. And an incident becomes a grounded :class:`~tulip.security.Evidence`
(:func:`xsoar_incident_to_finding`) — evidence, not a JSON blob the agent must
trust.

Live path: ``XSOAR_URL`` + ``XSOAR_API_KEY`` (plus ``XSOAR_API_KEY_ID`` for
Cortex 8.x / XSIAM) -> the XSOAR REST API. Verified against a mocked HTTP
transport for request shape + response parsing; adjust paths per deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from tulip.reasoning.gsar import Partition
from tulip.security import (
    GroundedFinding,
    Severity,
    ToolAdapter,
    as_json,
    env,
    ground_finding,
    inference_claim,
    tool_match,
)
from tulip.tools import tool

# XSOAR severity (0-4) -> Tulip band.
_SEV_BAND = {
    0: Severity.LOW,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}
_RISKY_SEVERITY = 3  # XSOAR "High" and above ground to a finding.

# Benign, invented offline incidents — XSOAR incident shape (subset).
_OFFLINE_INCIDENTS: dict[str, dict[str, object]] = {
    "INC-1001": {
        "id": "INC-1001",
        "name": "Impossible travel for svc-backup",
        "type": "Unauthorized Access",
        "severity": 3,
        "status": 1,  # active
        "owner": "soc-tier1",
        "details": "Sign-in from 198.51.100.23 (US) 4m after a sign-in from 203.0.113.9 (DE).",
        "labels": ["impossible_travel", "identity"],
    },
    "INC-1002": {
        "id": "INC-1002",
        "name": "Benign EICAR test detection",
        "type": "Malware",
        "severity": 1,
        "status": 1,
        "owner": "soc-tier1",
        "details": "EDR flagged the EICAR test file on a sandbox host; no spread observed.",
        "labels": ["test"],
    },
}


def xsoar_get_incident(incident_id: str) -> dict[str, object]:
    """Fetch one XSOAR incident; offline sample when no credentials."""
    url, key = env("XSOAR_URL"), env("XSOAR_API_KEY")
    if url and key:
        return _xsoar_live_get(url, key, incident_id)
    inc = _OFFLINE_INCIDENTS.get(incident_id)
    return {"source": "offline-sample", "incident": inc or {}, "found": inc is not None}


def xsoar_search_incidents(query: str = "", *, page_size: int = 50) -> dict[str, object]:
    """Search XSOAR incidents (query is matched against the offline sample)."""
    url, key = env("XSOAR_URL"), env("XSOAR_API_KEY")
    if url and key:
        return _xsoar_live_search(url, key, query, page_size)
    needle = query.lower()
    matched = [
        inc
        for inc in _OFFLINE_INCIDENTS.values()
        if needle in ("", "*") or needle in as_json(inc).lower()
    ]
    return {
        "query": query,
        "source": "offline-sample",
        "total": len(matched[:page_size]),
        "incidents": matched[:page_size],
    }


def xsoar_close_incident(
    incident_id: str, *, reason: str = "resolved by agent"
) -> dict[str, object]:
    """Close an XSOAR incident — a **write**. ``approve()`` it first.

    Offline: a simulated receipt (no state mutated). Live: POSTs the close action.
    """
    url, key = env("XSOAR_URL"), env("XSOAR_API_KEY")
    if url and key:
        return _xsoar_live_close(url, key, incident_id, reason)
    return {
        "incident_id": incident_id,
        "closed": True,
        "reason": reason,
        "source": "offline-sample",
    }


def xsoar_incident_to_finding(incident_id: str) -> GroundedFinding:
    """Ground an XSOAR incident into a typed Evidence (or abstain on a low-severity one).

    High-severity (>=3) incident -> tool-backed evidence -> Evidence. Lower ->
    inference-only -> Abstention. The agent acts on grounded evidence, not a raw
    SOAR verdict it must trust.
    """
    rec = xsoar_get_incident(incident_id)
    inc = cast("dict[str, object]", rec.get("incident") or {})
    severity_raw = inc.get("severity", 0)
    severity = severity_raw if isinstance(severity_raw, int) else 0
    risky = severity >= _RISKY_SEVERITY
    ref = f"tool:xsoar_get_incident:{incident_id}"
    if risky:
        evidence = (
            f"XSOAR incident {incident_id} '{inc.get('name')}' "
            f"(type={inc.get('type')}, severity={severity}): {inc.get('details')}"
        )
        partition = Partition(grounded=[tool_match(evidence, ref)])
    else:
        partition = Partition(
            ungrounded=[
                inference_claim(f"XSOAR incident {incident_id} is below the grounding bar.", ref)
            ]
        )
    return ground_finding(
        title=f"SOAR incident: {inc.get('name') or incident_id}",
        description=f"Palo Alto Cortex XSOAR incident {incident_id}.",
        severity=_SEV_BAND.get(severity, Severity.LOW),
        asset=str(incident_id),
        remediation="Triage in the SOC; escalate or close per playbook after review.",
        partition=partition,
    )


def _xsoar_headers(key: str) -> dict[str, str]:
    headers = {"Authorization": key, "Content-Type": "application/json"}
    key_id = env("XSOAR_API_KEY_ID")  # Cortex 8.x / XSIAM advanced auth
    if key_id:
        headers["x-xdr-auth-id"] = key_id
    return headers


def _xsoar_live_get(url: str, key: str, incident_id: str) -> dict[str, object]:
    import httpx

    with httpx.Client(base_url=url, headers=_xsoar_headers(key), timeout=30.0) as client:
        resp = client.post("/incident/search", json={"filter": {"id": [incident_id]}})
        resp.raise_for_status()
        data = resp.json().get("data") or []
    inc = data[0] if data else {}
    return {"source": "cortex-xsoar", "incident": inc, "found": bool(inc)}


def _xsoar_live_search(url: str, key: str, query: str, page_size: int) -> dict[str, object]:
    import httpx

    with httpx.Client(base_url=url, headers=_xsoar_headers(key), timeout=30.0) as client:
        resp = client.post(
            "/incident/search",
            json={"filter": {"query": query, "size": page_size}},
        )
        resp.raise_for_status()
        data = resp.json().get("data") or []
    return {"query": query, "source": "cortex-xsoar", "total": len(data), "incidents": data}


def _xsoar_live_close(url: str, key: str, incident_id: str, reason: str) -> dict[str, object]:
    import httpx

    with httpx.Client(base_url=url, headers=_xsoar_headers(key), timeout=30.0) as client:
        resp = client.post(
            "/incident/close",
            json={"id": incident_id, "closeReason": reason},
        )
        resp.raise_for_status()
    return {"incident_id": incident_id, "closed": True, "reason": reason, "source": "cortex-xsoar"}


@tool(name="xsoar_get_incident", description="Fetch a Palo Alto Cortex XSOAR incident by id")
async def xsoar_incident_tool(incident_id: str) -> str:
    """Tool wrapper: returns the incident as a JSON string."""
    return as_json(xsoar_get_incident(incident_id))


@tool(name="xsoar_search_incidents", description="Search Palo Alto Cortex XSOAR incidents")
async def xsoar_search_tool(query: str = "") -> str:
    """Tool wrapper: returns matching incidents as a JSON string."""
    return as_json(xsoar_search_incidents(query))


@tool(
    name="xsoar_close_incident",
    description="Close a Cortex XSOAR incident (a write — gate it through approval)",
    idempotent=True,
)
async def xsoar_close_tool(incident_id: str, reason: str = "resolved by agent") -> str:
    """Tool wrapper: closes an incident and returns a JSON receipt."""
    return as_json(xsoar_close_incident(incident_id, reason=reason))


def xsoar_adapter() -> ToolAdapter:
    """The :class:`~tulip.security.SecurityAdapter` for this integration."""
    return ToolAdapter(
        name="cortex_xsoar",
        vendor="Palo Alto Cortex XSOAR",
        _tools=[xsoar_incident_tool, xsoar_search_tool, xsoar_close_tool],
    )


@dataclass(frozen=True)
class CortexXSOAR:
    """A small façade for vendor-agnostic SOAR access in investigation code."""

    async def get_incident(self, incident_id: str) -> dict[str, object]:
        return xsoar_get_incident(incident_id)

    async def search(self, query: str = "") -> dict[str, object]:
        return xsoar_search_incidents(query)

    async def close(
        self, incident_id: str, *, reason: str = "resolved by agent"
    ) -> dict[str, object]:
        return xsoar_close_incident(incident_id, reason=reason)


__all__ = [
    "CortexXSOAR",
    "xsoar_adapter",
    "xsoar_close_incident",
    "xsoar_close_tool",
    "xsoar_get_incident",
    "xsoar_incident_to_finding",
    "xsoar_incident_tool",
    "xsoar_search_incidents",
    "xsoar_search_tool",
]


if __name__ == "__main__":
    print(as_json(xsoar_search_incidents("travel")))
