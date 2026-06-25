# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""SOAR integrations — incident orchestration & response (Cortex XSOAR, …)."""

from tulip_integrations.soar.cortex_xsoar import (
    CortexXSOAR,
    xsoar_adapter,
    xsoar_close_incident,
    xsoar_close_tool,
    xsoar_get_incident,
    xsoar_incident_to_finding,
    xsoar_incident_tool,
    xsoar_search_incidents,
    xsoar_search_tool,
)

__all__ = [
    "CortexXSOAR",
    "xsoar_adapter",
    "xsoar_close_incident",
    "xsoar_close_tool",
    "xsoar_get_incident",
    "xsoar_incident_to_finding",
    "xsoar_incident_tool",
    "xsoar_search_incidents",
    "xsoar_search_tool",
]
