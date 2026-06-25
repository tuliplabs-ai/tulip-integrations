# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Okta identity integration — the surface most attacks touch.

Implements the core ``IdentitySource`` port so it drops into
``SecurityContext(identity=OktaIdentity())``. With ``OKTA_URL`` + ``OKTA_TOKEN``
set it queries the Okta API; with neither set it returns a benign offline
reference (a low-risk and a high-risk sample user) so it runs in CI with no
credentials.

``disable`` is a **write** — gate it through ``ctx.actions`` / ``approve()``.
LIVE PATH: exercised against a mocked HTTP transport in
``tests/test_live_paths.py`` (request shape + response parsing verified); not
yet run against a real Okta tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tulip.security import ToolAdapter, as_json, env
from tulip.tools import tool

# Benign offline sample (RFC 5737 docs IPs).
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


def _record(user: str) -> dict[str, Any]:
    return _SAMPLE.get(user, {"risk": "unknown", "mfa": None, "signins": []})


def _live(path: str) -> dict[str, Any] | None:
    url, token = env("OKTA_URL"), env("OKTA_TOKEN")
    if not (url and token):
        return None
    import httpx

    with httpx.Client(base_url=url, headers={"Authorization": f"SSWS {token}"}, timeout=30.0) as c:
        resp = c.get(path)
        resp.raise_for_status()
        return {"source": "okta", "data": resp.json()}


def okta_get_user(user: str) -> dict[str, Any]:
    live = _live(f"/api/v1/users/{user}")
    if live is not None:
        return live
    return {"user": user, "source": "offline-sample", **_record(user)}


def okta_risk(user: str) -> dict[str, Any]:
    rec = _record(user)
    return {
        "user": user,
        "risk": rec["risk"],
        "impossible_travel": rec.get("impossible_travel", False),
    }


def okta_signins(user: str) -> dict[str, Any]:
    live = _live(f"/api/v1/users/{user}/logs")
    if live is not None:
        return live
    return {"user": user, "signins": _record(user).get("signins", [])}


def okta_disable(user: str) -> dict[str, Any]:
    # A write — approve() it first. Offline: simulated receipt.
    return {"user": user, "disabled": True, "source": "offline-sample"}


@tool(name="okta_get_user", description="Fetch an Okta user's profile + risk signals")
async def okta_user_tool(user: str) -> str:
    return as_json(okta_get_user(user))


@tool(
    name="okta_disable_user",
    description="Disable an Okta user (a write — gate it)",
    idempotent=True,
)
async def okta_disable_tool(user: str) -> str:
    return as_json(okta_disable(user))


@dataclass(frozen=True)
class OktaIdentity:
    """A :class:`~tulip.security.SecurityContext` ``IdentitySource`` via Okta."""

    async def get_user(self, user: str) -> dict[str, Any]:
        return okta_get_user(user)

    async def risk(self, user: str) -> dict[str, Any]:
        return okta_risk(user)

    async def signins(self, user: str) -> dict[str, Any]:
        return okta_signins(user)

    async def disable(self, user: str) -> dict[str, Any]:
        return okta_disable(user)


def okta_adapter() -> ToolAdapter:
    return ToolAdapter(
        name="okta", vendor="Okta identity", _tools=[okta_user_tool, okta_disable_tool]
    )


__all__ = [
    "OktaIdentity",
    "okta_adapter",
    "okta_disable",
    "okta_disable_tool",
    "okta_get_user",
    "okta_risk",
    "okta_signins",
    "okta_user_tool",
]
