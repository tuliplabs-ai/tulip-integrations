# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Slack notify integration (offline — httpx mocked)."""

from __future__ import annotations

from typing import Any

import pytest

from tulip_integrations.notify import notify_finding, slack_notify


def test_slack_notify_requires_a_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    with pytest.raises(RuntimeError):
        slack_notify("anyone there?")


class _Resp:
    status_code = 200

    def raise_for_status(self) -> None:  # noqa: D401
        return None


class _Client:
    last: dict[str, Any] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *args: Any) -> bool:
        return False

    def post(self, url: str, json: dict[str, Any]) -> _Resp:
        _Client.last = {"url": url, "json": json}
        return _Resp()


def test_notify_finding_formats_and_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/xxx")
    import httpx

    monkeypatch.setattr(httpx, "Client", _Client)
    out = notify_finding({"severity": "high", "title": "Root MFA disabled", "asset": "aws:root"})
    assert out["ok"]
    assert out["status"] == 200
    text = _Client.last["json"]["text"]
    assert "HIGH" in text
    assert "Root MFA disabled" in text
    assert "aws:root" in text
