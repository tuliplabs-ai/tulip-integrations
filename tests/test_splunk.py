# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Conformance + behavior tests for the Splunk integration.

Uses the core conformance kit (`tulip.security.testing`) to prove the adapter
satisfies the contract — the langchain-tests pattern. Runs offline.
"""

from __future__ import annotations

from tulip.security import security_toolset
from tulip.security.testing import assert_adapter_conformance, assert_tool_returns_json

from tulip_integrations.playbooks import splunk_threat_hunt
from tulip_integrations.siem.splunk import splunk_adapter, splunk_search, splunk_siem_tool


def test_adapter_conforms_to_core_contract() -> None:
    assert_adapter_conformance(splunk_adapter())


def test_offline_search_filters_sample() -> None:
    out = splunk_search("powershell")
    assert out["source"] == "offline-sample"
    assert out["count"] >= 1
    assert all("powershell" in str(e).lower() for e in out["events"])


async def test_tool_returns_json() -> None:
    payload = await assert_tool_returns_json(splunk_siem_tool, "failed logons")
    assert "events" in payload
    assert payload["source"] == "offline-sample"


def test_plugs_into_core_toolset_via_extra() -> None:
    # Core's SIEM off; the external Splunk tool merged in explicitly.
    names = {t.name for t in security_toolset(siem=False, extra=splunk_adapter().tools())}
    assert "splunk_search" in names
    assert "query_siem" not in names


def test_community_playbook_references_known_tools() -> None:
    pb = splunk_threat_hunt()
    referenced = {t for step in pb.steps for t in step.expected_tools}
    # splunk_search comes from this integration; enrich_indicator from core.
    assert "splunk_search" in referenced
    assert "enrich_indicator" in referenced
