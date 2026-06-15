# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Live Auth0 check — runs only when Auth0 creds are set (skips in CI).

Verified live on 2026-06-15 (client_credentials grant + Management API). Re-run with:
    AUTH0_DOMAIN=... AUTH0_CLIENT_ID=... AUTH0_CLIENT_SECRET=... \
        pytest tests/test_live_auth0.py
or with a static dashboard token:
    AUTH0_MGMT_TOKEN=... pytest tests/test_live_auth0.py
"""

from __future__ import annotations

import os

import pytest

from tulip_integrations.identity.auth0 import Auth0Identity, _mgmt_token

_HAS_CREDS = bool(
    os.environ.get("AUTH0_MGMT_TOKEN")
    or (
        os.environ.get("AUTH0_DOMAIN")
        and os.environ.get("AUTH0_CLIENT_ID")
        and os.environ.get("AUTH0_CLIENT_SECRET")
    )
)

pytestmark = pytest.mark.skipif(
    not _HAS_CREDS,
    reason="set AUTH0_MGMT_TOKEN or AUTH0_DOMAIN/CLIENT_ID/CLIENT_SECRET to run the live Auth0 check",
)


def test_live_token_exchange() -> None:
    # A real Management API token resolves (static env token or client_credentials grant).
    assert _mgmt_token(), "no token — Management API grant likely missing"


async def test_live_user_lookup_hits_management_api() -> None:
    # A nonexistent email still proves the live path: an empty list from /users-by-email.
    rec = await Auth0Identity().get_user("nobody-probe@example.com")
    assert rec["source"] == "auth0"
