# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""The first-wave vendor providers satisfy their SecurityContext ports and run
offline — so a SecurityContext can be assembled entirely from real vendors and
investigation code stays vendor-agnostic.
"""

from __future__ import annotations

from pytest import MonkeyPatch
from tulip.security import (
    EndpointSource,
    IdentitySource,
    SecurityContext,
    ThreatIntelSource,
)

from tulip_integrations.edr.crowdstrike import CrowdStrikeEndpoint, crowdstrike_adapter
from tulip_integrations.identity.auth0 import Auth0Identity, auth0_adapter
from tulip_integrations.identity.okta import OktaIdentity, okta_adapter
from tulip_integrations.threat_intel.virustotal import VirusTotalIntel, virustotal_adapter


def test_providers_satisfy_their_ports() -> None:
    assert isinstance(CrowdStrikeEndpoint(), EndpointSource)
    assert isinstance(OktaIdentity(), IdentitySource)
    assert isinstance(Auth0Identity(), IdentitySource)
    assert isinstance(VirusTotalIntel(), ThreatIntelSource)


async def test_auth0_identity_offline(monkeypatch: MonkeyPatch) -> None:
    # Hermetic: force the offline fallback even when a dev shell has live Auth0 creds.
    for var in ("AUTH0_MGMT_TOKEN", "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    ctx = SecurityContext(identity=Auth0Identity())
    rec = await ctx.identity.get_user("mallory@example.com")
    assert rec["source"] == "offline-sample"
    assert (await ctx.identity.risk("mallory@example.com"))["risk"] == "high"


async def test_a_fully_vendor_backed_context_works_offline() -> None:
    ctx = SecurityContext(
        endpoint=CrowdStrikeEndpoint(),
        identity=OktaIdentity(),
        threat_intel=VirusTotalIntel(),
    )
    host = await ctx.endpoint.get_host("WS-0142")
    assert host["source"] == "offline-sample"
    risk = await ctx.identity.risk("mallory@example.com")
    assert risk["risk"] == "high"
    intel = await ctx.threat_intel.enrich("198.51.100.23")
    assert isinstance(intel, dict)


async def test_endpoint_isolate_and_identity_disable_are_simulated_offline() -> None:
    assert (await CrowdStrikeEndpoint().isolate("host-1"))["source"] == "offline-sample"
    assert (await OktaIdentity().disable("mallory@example.com"))["disabled"] is True


def test_adapters_conform() -> None:
    from tulip.security.testing import assert_adapter_conformance

    for adapter in (crowdstrike_adapter(), okta_adapter(), auth0_adapter(), virustotal_adapter()):
        assert_adapter_conformance(adapter)
