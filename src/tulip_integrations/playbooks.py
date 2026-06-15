# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Community playbooks contributed alongside integrations.

Playbooks are content — a community contributor can drop a `Playbook` factory
(or a YAML loaded with `tulip.playbooks.load_playbook`) here, referencing this
integration's tools plus core's bundled ones in ``expected_tools``.
"""

from __future__ import annotations

from tulip.playbooks import Playbook, PlaybookStep


def splunk_threat_hunt() -> Playbook:
    """Hunt in Splunk, then enrich what surfaces with core's IOC tool."""
    return Playbook(
        id="splunk_threat_hunt",
        name="Splunk threat hunt",
        description="Search Splunk for a suspicious pattern, then enrich the "
        "indicators it surfaces — a community playbook spanning this integration "
        "(splunk_search) and a core bundled tool (enrich_indicator).",
        steps=[
            PlaybookStep(
                id="hunt",
                description="Search Splunk for the suspicious pattern.",
                expected_tools=["splunk_search"],
                hints=["Start narrow (host + time window), then widen."],
            ),
            PlaybookStep(
                id="enrich",
                description="Enrich the indicators the hunt surfaced.",
                expected_tools=["enrich_indicator"],
            ),
        ],
        allow_extra_tools=True,
        tags=["community", "siem", "splunk", "threat-hunt"],
    )


def ai_spm_review() -> Playbook:
    """Review AI security posture: inventory the AI-BOM, then triage Wiz issues."""
    return Playbook(
        id="ai_spm_review",
        name="AI security posture review (Wiz)",
        description="Inventory the AI assets Wiz discovered, pull the posture "
        "issues, and ground them into typed findings — agentic reasoning over "
        "your AI-SPM data.",
        steps=[
            PlaybookStep(
                id="inventory",
                description="List the AI assets (AI-BOM) in scope.",
                expected_tools=["wiz_inventory"],
                hints=["Flag publicly-exposed model endpoints first."],
            ),
            PlaybookStep(
                id="issues",
                description="Pull the open AI-SPM issues, highest severity first.",
                expected_tools=["wiz_issues"],
            ),
            PlaybookStep(
                id="enrich",
                description="Enrich any indicators the issues reference.",
                expected_tools=["enrich_indicator"],
                required=False,
            ),
        ],
        allow_extra_tools=True,
        tags=["community", "ai-spm", "wiz", "posture"],
    )


__all__ = ["ai_spm_review", "splunk_threat_hunt"]
