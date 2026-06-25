# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Cortex XSOAR adapter — offline behaviour, conformance, and grounding."""

from __future__ import annotations

from tulip.security import is_finding
from tulip.security.testing import assert_adapter_conformance, assert_tool_returns_json

from tulip_integrations.soar.cortex_xsoar import (
    xsoar_adapter,
    xsoar_close_incident,
    xsoar_close_tool,
    xsoar_get_incident,
    xsoar_incident_to_finding,
    xsoar_incident_tool,
    xsoar_search_incidents,
    xsoar_search_tool,
)


def test_offline_get_incident_shape() -> None:
    out = xsoar_get_incident("INC-1001")
    assert out["found"] is True
    assert out["source"] == "offline-sample"
    assert out["incident"]["severity"] == 3


def test_offline_get_unknown_incident() -> None:
    out = xsoar_get_incident("INC-9999")
    assert out["found"] is False
    assert out["incident"] == {}


def test_offline_search_filters() -> None:
    assert xsoar_search_incidents("travel")["total"] == 1
    assert xsoar_search_incidents("")["total"] == 2  # everything


def test_close_is_a_simulated_write_offline() -> None:
    out = xsoar_close_incident("INC-1001", reason="false positive")
    assert out["closed"] is True
    assert out["reason"] == "false positive"
    assert out["source"] == "offline-sample"


def test_high_severity_incident_grounds_to_finding() -> None:
    result = xsoar_incident_to_finding("INC-1001")  # severity 3 -> finding
    assert is_finding(result)


def test_low_severity_incident_abstains() -> None:
    result = xsoar_incident_to_finding("INC-1002")  # severity 1 -> abstention
    assert not is_finding(result)


def test_adapter_conformance() -> None:
    assert_adapter_conformance(xsoar_adapter())


async def test_tools_return_json() -> None:
    assert (await assert_tool_returns_json(xsoar_incident_tool, "INC-1001"))["found"] is True
    assert "incidents" in await assert_tool_returns_json(xsoar_search_tool, "travel")
    assert (await assert_tool_returns_json(xsoar_close_tool, "INC-1001"))["closed"] is True
