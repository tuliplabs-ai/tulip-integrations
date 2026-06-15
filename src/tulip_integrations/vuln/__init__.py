# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability / CNAPP / AI-SPM integrations (Wiz, Tenable, …)."""

from tulip_integrations.vuln.wiz import (
    wiz_adapter,
    wiz_inventory,
    wiz_inventory_tool,
    wiz_issues,
    wiz_issues_tool,
    wiz_to_findings,
)

__all__ = [
    "wiz_adapter",
    "wiz_inventory",
    "wiz_inventory_tool",
    "wiz_issues",
    "wiz_issues_tool",
    "wiz_to_findings",
]
