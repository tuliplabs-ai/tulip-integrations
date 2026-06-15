# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""A vendor provider plugs into the core SecurityContext facade.

Proves the domain-layout payoff: investigation code written against
``ctx.logs.search(...)`` runs unchanged whether the provider is the bundled
offline reference or a real vendor (here, Splunk).
"""

from __future__ import annotations

from tulip.security import LogSource, SecurityContext

from tulip_integrations.siem.splunk import SplunkLogs


def test_splunk_provider_satisfies_the_logsource_port() -> None:
    assert isinstance(SplunkLogs(), LogSource)


async def test_security_context_accepts_an_injected_vendor_provider() -> None:
    ctx = SecurityContext(logs=SplunkLogs())
    result = await ctx.logs.search("powershell", window="6h")
    assert isinstance(result, dict)
    assert "events" in result
    # offline (no SPLUNK_URL/TOKEN) -> deterministic sample channel
    assert result["source"] == "offline-sample"
