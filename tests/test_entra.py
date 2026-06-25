# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Microsoft Entra integration — offline + grounding behavior.

The defining check: a risky user grounds into a typed Finding; a clean user
abstains. The connector never emits an ungrounded identity verdict.
"""
from __future__ import annotations

from tulip.security import is_finding

from tulip_integrations.identity.entra import (
    EntraIdentity,
    entra_adapter,
    entra_get_user,
    entra_risk_to_finding,
)


def test_entra_offline_user_shape() -> None:
    u = entra_get_user("mallory@example.com")
    assert u["source"] == "offline-sample"
    assert u["risk"] == "high"


def test_entra_risk_grounds_high_risk_user() -> None:
    finding = entra_risk_to_finding("mallory@example.com")
    assert is_finding(finding)  # risky -> tool-backed evidence -> ships
    assert finding.asset == "mallory@example.com"
    assert finding.evidence_refs
    assert finding.gsar_score >= 0.8


def test_entra_abstains_on_clean_user() -> None:
    result = entra_risk_to_finding("jsmith@example.com")
    assert not is_finding(result)  # no risk signal -> Abstention, no hallucinated finding
    assert "withheld" in result.reason


def test_entra_adapter_exposes_tools() -> None:
    assert len(entra_adapter().tools()) == 2
    assert entra_adapter().vendor == "Microsoft Entra ID"


async def test_entra_identity_port() -> None:
    ident = EntraIdentity()
    risk = await ident.risk("mallory@example.com")
    assert risk["risk"] == "high"
    assert risk["impossible_travel"] is True
