# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Conformance + behavior tests for the Wiz AI-SPM integration (offline)."""

from __future__ import annotations

from tulip.security import is_finding, security_toolset
from tulip.security.testing import assert_adapter_conformance, assert_tool_returns_json

from tulip_integrations.security import ai_spm_review
from tulip_integrations.security.wiz import (
    wiz_adapter,
    wiz_inventory,
    wiz_issues,
    wiz_issues_tool,
    wiz_to_findings,
)


def test_adapter_conforms_to_core_contract() -> None:
    assert_adapter_conformance(wiz_adapter())


def test_inventory_offline() -> None:
    out = wiz_inventory()
    assert out["source"] == "offline-sample"
    assert out["count"] >= 1
    assert any(a["type"] == "model-endpoint" for a in out["assets"])


def test_issues_severity_filter() -> None:
    crit = wiz_issues(severity="CRITICAL")
    assert crit["count"] >= 1
    assert all(i["severity"] == "CRITICAL" for i in crit["issues"])


async def test_issues_tool_returns_json() -> None:
    payload = await assert_tool_returns_json(wiz_issues_tool)
    assert "issues" in payload


def test_wiz_issues_ground_into_typed_findings() -> None:
    findings = wiz_to_findings()
    assert findings  # offline issues all carry evidence → they ship
    assert all(is_finding(f) for f in findings)
    crit = [f for f in findings if is_finding(f) and f.title.startswith("Publicly exposed")]
    assert crit and crit[0].taxonomy  # tagged to a threat catalogue


def test_plugs_into_core_toolset_via_extra() -> None:
    names = {t.name for t in security_toolset(extra=wiz_adapter().tools())}
    assert {"wiz_inventory", "wiz_issues"} <= names


def test_ai_spm_playbook_references_known_tools() -> None:
    referenced = {t for step in ai_spm_review().steps for t in step.expected_tools}
    assert "wiz_inventory" in referenced
    assert "wiz_issues" in referenced
