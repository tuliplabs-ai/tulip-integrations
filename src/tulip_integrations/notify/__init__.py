# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Notify / handoff integrations — reach a human or a ticket when an agent needs to.

The end of the SOC loop: after a finding is grounded, verified, and admitted, a
notify integration hands it off to a human (or a ticket/page). Live-only — no
fake offline sample.
"""

from tulip_integrations.notify.slack import (
    notify_finding,
    slack_adapter,
    slack_notify,
    slack_notify_tool,
)

__all__ = ["notify_finding", "slack_adapter", "slack_notify", "slack_notify_tool"]
