# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""EDR integrations — host forensics + containment (CrowdStrike, …)."""

from tulip_integrations.edr.crowdstrike import (
    CrowdStrikeEndpoint,
    crowdstrike_adapter,
    cs_detections,
    cs_detections_tool,
    cs_host_timeline,
    cs_host_tool,
    cs_isolate,
    cs_isolate_tool,
)

__all__ = [
    "CrowdStrikeEndpoint",
    "crowdstrike_adapter",
    "cs_detections",
    "cs_detections_tool",
    "cs_host_timeline",
    "cs_host_tool",
    "cs_isolate",
    "cs_isolate_tool",
]
