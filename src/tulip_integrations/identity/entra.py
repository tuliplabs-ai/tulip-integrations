# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Microsoft Entra ID (Azure AD) identity integration — the enterprise default.

Implements the core ``IdentitySource`` port so it drops into
``SecurityContext(identity=EntraIdentity())``. With ``ENTRA_TOKEN`` set it
queries Microsoft Graph (v1.0); with none set it returns a benign offline
reference (a low-risk and a high-risk sample user) so it runs in CI with no
credentials.

Unlike a raw connector, ``entra_risk_to_finding`` GROUNDS the identity-risk
signal: a risky / impossible-travel user becomes tool-backed evidence that
clears GSAR (-> a typed ``Evidence``); a clean user abstains. That keeps the
integration on the "trusted agents" side of the line — evidence or abstain,
never a raw verdict.

``disable`` is a **write** (Graph ``PATCH /users/{id}`` ``accountEnabled=false``)
— gate it through ``ctx.actions`` / ``approve()``. LIVE PATH: request/response
shapes mirror Microsoft Graph v1.0; verified offline (not yet against a live
tenant).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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

_GRAPH = "https://graph.microsoft.com/v1.0"

# Benign offline sample (RFC 5737 docs IPs), shape-compatible with Okta/Auth0.
_SAMPLE: dict[str, dict[str, Any]] = {
    "jsmith@example.com": {
        "risk": "low",
        "mfa": True,
        "signins": [{"ip": "198.51.100.10", "city": "Toronto", "result": "success"}],
    },
    "mallory@example.com": {
        "risk": "high",
        "mfa": False,
        "impossible_travel": True,
        "signins": [
            {"ip": "203.0.113.7", "city": "Toronto", "result": "success"},
            {"ip": "192.0.2.55", "city": "Minsk", "result": "success"},
        ],
    },
}

_RISKY = {"high", "medium"}


def _record(user: str) -> dict[str, Any]:
    return _SAMPLE.get(user, {"risk": "unknown", "mfa": None, "signins": []})


def _live(path: str) -> dict[str, Any] | None:
    token = env("ENTRA_TOKEN")
    if not token:
        return None
    import httpx

    with httpx.Client(
        base_url=_GRAPH, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as c:
        resp = c.get(path)
        resp.raise_for_status()
        return {"source": "microsoft-graph", "data": resp.json()}


def entra_get_user(user: str) -> dict[str, Any]:
    live = _live(f"/users/{user}")
    if live is not None:
        return live
    return {"user": user, "source": "offline-sample", **_record(user)}


def entra_risk(user: str) -> dict[str, Any]:
    rec = _record(user)
    return {
        "user": user,
        "risk": rec["risk"],
        "impossible_travel": rec.get("impossible_travel", False),
        "mfa": rec.get("mfa"),
    }


def entra_signins(user: str) -> dict[str, Any]:
    live = _live(f"/auditLogs/signIns?$filter=userPrincipalName eq '{user}'")
    if live is not None:
        return live
    return {"user": user, "signins": _record(user).get("signins", [])}


def entra_disable(user: str) -> dict[str, Any]:
    # A write (PATCH accountEnabled=false) — approve() it first. Offline: simulated receipt.
    return {"user": user, "disabled": True, "source": "offline-sample"}


def entra_risk_to_finding(user: str) -> GroundedFinding:
    """Ground an Entra identity-risk signal into a typed Evidence (or abstain).

    Risky / impossible-travel -> tool-backed evidence -> Evidence. Clean ->
    inference-only -> Abstention. This is the differentiator: identity risk is
    evidence-grounded, not a raw JSON verdict the agent must trust.
    """
    rec = entra_risk(user)
    risky = rec["risk"] in _RISKY or bool(rec.get("impossible_travel"))
    ref = f"tool:entra_risk:{user}"
    if risky:
        evidence = (
            f"Entra flagged {user}: riskLevel={rec['risk']}, "
            f"impossibleTravel={rec.get('impossible_travel')}, mfa={rec.get('mfa')}"
        )
        partition = Partition(grounded=[tool_match(evidence, ref)])
    else:
        partition = Partition(
            ungrounded=[inference_claim(f"No Entra risk signal observed for {user}.", ref)]
        )
    return ground_finding(
        title=f"Risky identity signal: {user}",
        description=f"Microsoft Entra risk assessment for {user}.",
        severity=Severity.HIGH if risky else Severity.LOW,
        asset=user,
        remediation="Force re-authentication with MFA, revoke active sessions, and review recent sign-ins.",
        partition=partition,
    )


@tool(name="entra_get_user", description="Fetch a Microsoft Entra user's profile + risk signals")
async def entra_user_tool(user: str) -> str:
    return as_json(entra_get_user(user))


@tool(
    name="entra_disable_user",
    description="Disable a Microsoft Entra user (a write — gate it)",
    idempotent=True,
)
async def entra_disable_tool(user: str) -> str:
    return as_json(entra_disable(user))


@dataclass(frozen=True)
class EntraIdentity:
    """A :class:`~tulip.security.SecurityContext` ``IdentitySource`` via Microsoft Entra."""

    async def get_user(self, user: str) -> dict[str, Any]:
        return entra_get_user(user)

    async def risk(self, user: str) -> dict[str, Any]:
        return entra_risk(user)

    async def signins(self, user: str) -> dict[str, Any]:
        return entra_signins(user)

    async def disable(self, user: str) -> dict[str, Any]:
        return entra_disable(user)


def entra_adapter() -> ToolAdapter:
    return ToolAdapter(
        name="entra", vendor="Microsoft Entra ID", _tools=[entra_user_tool, entra_disable_tool]
    )


__all__ = [
    "EntraIdentity",
    "entra_adapter",
    "entra_disable",
    "entra_disable_tool",
    "entra_get_user",
    "entra_risk",
    "entra_risk_to_finding",
    "entra_signins",
    "entra_user_tool",
]
