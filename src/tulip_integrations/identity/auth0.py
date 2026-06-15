# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Auth0 identity integration (Okta's developer identity platform).

Implements the core ``IdentitySource`` port so it drops into
``SecurityContext(identity=Auth0Identity())``. Auth0 uses an OAuth2 token
against the Management API (distinct from the Okta SSWS API). The token is
resolved in this order:

1. ``AUTH0_MGMT_TOKEN`` — a Management API token (e.g. copied from the
   dashboard's *API Explorer* tab; the zero-setup path).
2. ``AUTH0_DOMAIN`` + ``AUTH0_CLIENT_ID`` + ``AUTH0_CLIENT_SECRET`` — a
   machine-to-machine app authorized for the Management API
   (``client_credentials`` grant).
3. None set → benign offline reference sample (a low-risk and a high-risk user).

``disable`` is a **write** (blocks the user) — gate it through ``ctx.actions`` /
``approve()``. Live path verified 2026-06-15 (client_credentials grant + Management
API ``/users-by-email``) — see ``tests/test_live_auth0.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tulip.security import ToolAdapter, as_json, env
from tulip.tools import tool

# Benign offline sample (RFC 5737 docs IPs).
_SAMPLE: dict[str, dict[str, Any]] = {
    "jsmith@example.com": {"risk": "low", "blocked": False, "last_ip": "198.51.100.10"},
    "mallory@example.com": {"risk": "high", "blocked": False, "impossible_travel": True,
                            "last_ip": "192.0.2.55"},
}


def _domain() -> str | None:
    return env("AUTH0_DOMAIN")


def _mgmt_token() -> str | None:
    """A Management API token from a static env token or a client-credentials grant."""
    tok = env("AUTH0_MGMT_TOKEN")
    if tok:
        return tok
    dom, cid, sec = _domain(), env("AUTH0_CLIENT_ID"), env("AUTH0_CLIENT_SECRET")
    if not (dom and cid and sec):
        return None
    import httpx

    resp = httpx.post(
        f"https://{dom}/oauth/token",
        json={
            "client_id": cid,
            "client_secret": sec,
            "audience": f"https://{dom}/api/v2/",
            "grant_type": "client_credentials",
        },
        timeout=30.0,
    )
    if resp.status_code != 200:
        return None
    token = resp.json().get("access_token")
    return str(token) if token else None


def _live_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    dom, token = _domain(), _mgmt_token()
    if not (dom and token):
        return None
    import httpx

    resp = httpx.get(
        f"https://{dom}/api/v2{path}",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30.0,
    )
    resp.raise_for_status()
    return {"source": "auth0", "data": resp.json()}


def _record(user: str) -> dict[str, Any]:
    return _SAMPLE.get(user, {"risk": "unknown", "blocked": None})


def auth0_get_user(user: str) -> dict[str, Any]:
    live = _live_get("/users-by-email", {"email": user})
    if live is not None:
        return live
    return {"user": user, "source": "offline-sample", **_record(user)}


def auth0_risk(user: str) -> dict[str, Any]:
    rec = _record(user)
    return {"user": user, "risk": rec["risk"], "impossible_travel": rec.get("impossible_travel", False)}


def auth0_signins(user: str) -> dict[str, Any]:
    live = _live_get("/logs", {"q": f'user_id:"{user}"', "per_page": 5})
    if live is not None:
        return live
    return {"user": user, "source": "offline-sample", "signins": [{"ip": _record(user).get("last_ip")}]}


def auth0_disable(user: str) -> dict[str, Any]:
    # A write — approve() it first. Offline: simulated receipt.
    return {"user": user, "blocked": True, "source": "offline-sample"}


@tool(name="auth0_get_user", description="Fetch an Auth0 user (by email) + status")
async def auth0_user_tool(user: str) -> str:
    return as_json(auth0_get_user(user))


@tool(name="auth0_disable_user", description="Block an Auth0 user (a write — gate it)", idempotent=True)
async def auth0_disable_tool(user: str) -> str:
    return as_json(auth0_disable(user))


@dataclass(frozen=True)
class Auth0Identity:
    """A :class:`~tulip.security.SecurityContext` ``IdentitySource`` via Auth0."""

    async def get_user(self, user: str) -> dict[str, Any]:
        return auth0_get_user(user)

    async def risk(self, user: str) -> dict[str, Any]:
        return auth0_risk(user)

    async def signins(self, user: str) -> dict[str, Any]:
        return auth0_signins(user)

    async def disable(self, user: str) -> dict[str, Any]:
        return auth0_disable(user)


def auth0_adapter() -> ToolAdapter:
    return ToolAdapter(name="auth0", vendor="Auth0 identity", _tools=[auth0_user_tool, auth0_disable_tool])


__all__ = [
    "Auth0Identity",
    "auth0_adapter",
    "auth0_disable",
    "auth0_disable_tool",
    "auth0_get_user",
    "auth0_risk",
    "auth0_signins",
    "auth0_user_tool",
]
