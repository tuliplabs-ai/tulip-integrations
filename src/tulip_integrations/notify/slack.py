# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Slack notify — the human-handoff leg of the SOC loop.

A grounded, verified finding is only useful if it reaches a human (or a ticket).
This closes the loop after ``admit()`` / on ``require_human``: it posts a finding
— or any message — to a Slack incoming webhook. It is **live-only**: with no
``SLACK_WEBHOOK_URL`` it raises rather than pretending to have notified anyone (a
notify leg has no meaningful offline sample — it either reaches a human or it
doesn't).

Set ``SLACK_WEBHOOK_URL`` (a Slack incoming webhook URL; ``NOTIFY_WEBHOOK_URL``
also works for any Slack-compatible sink) and call :func:`slack_notify` /
:func:`notify_finding`, or hand :data:`slack_notify_tool` to an agent.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tulip.security import ToolAdapter, as_json, env
from tulip.tools import tool


def slack_notify(text: str, *, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Post ``text`` to the Slack incoming webhook in ``SLACK_WEBHOOK_URL``.

    Live-only: raises ``RuntimeError`` if no webhook is configured.
    """
    url = env("SLACK_WEBHOOK_URL", "NOTIFY_WEBHOOK_URL")
    if not url:
        msg = "set SLACK_WEBHOOK_URL to a Slack incoming webhook"
        raise RuntimeError(msg)
    import httpx

    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
    return {"ok": True, "status": resp.status_code, "destination": "slack"}


_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


def notify_finding(finding: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Format a Evidence (or finding-shaped mapping) and post it to Slack."""
    get = finding.get if isinstance(finding, Mapping) else lambda k, d=None: getattr(finding, k, d)
    sev_raw = get("severity", "info")
    sev = str(getattr(sev_raw, "value", sev_raw) or "info")
    title = get("title", "<finding>")
    asset = get("asset", "")
    text = f"{_SEV_EMOJI.get(sev.lower(), '⚪')} *{sev.upper()}* — {title}"
    if asset:
        text += f"  (`{asset}`)"
    return slack_notify(text)


@tool(name="slack_notify", description="Post a security alert/message to the team's Slack channel")
async def slack_notify_tool(text: str) -> str:
    """Tool wrapper: post ``text`` to Slack, return the result as JSON."""
    return as_json(slack_notify(text))


def slack_adapter() -> ToolAdapter:
    """A :class:`~tulip.security.ToolAdapter` exposing the Slack notify tool."""
    return ToolAdapter(name="slack", vendor="Slack notify (human handoff)", _tools=[slack_notify_tool])


__all__ = ["notify_finding", "slack_adapter", "slack_notify", "slack_notify_tool"]
