# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""VirusTotal threat-intel integration — IOC reputation enrichment.

Implements the core ``ThreatIntelSource`` port so it drops into
``SecurityContext(threat_intel=VirusTotalIntel())``. With ``VT_API_KEY`` set it
queries the VirusTotal v3 API; with none set it returns the bundled, benign
offline reference (the core ``enrich_indicator`` sample) so it runs in CI with
no credentials.

VERIFIED: the live v3 path was confirmed against the VirusTotal API on
2026-06-15 (clean IP → 0 detections; EICAR hash → malicious). The live check is
re-runnable via ``tests/test_live_virustotal.py`` when ``VT_API_KEY`` is set
(it skips in CI, which has no key).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tulip.security import ToolAdapter, as_json, enrich_indicator, env
from tulip.tools import tool


def vt_enrich(indicator: str) -> dict[str, Any]:
    """Reputation/context for an IP, domain, or file hash.

    Live (``VT_API_KEY``): VirusTotal v3. Offline: the core reference sample.
    """
    key = env("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    if key:
        return _vt_live(key, indicator)
    out = enrich_indicator(indicator)
    out["source"] = "offline-sample"
    return out


def _vt_live(key: str, indicator: str) -> dict[str, Any]:
    import httpx

    kind = "ip_addresses" if indicator.replace(".", "").isdigit() else "domains"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdef" for c in indicator.lower()):
        kind = "files"
    with httpx.Client(base_url="https://www.virustotal.com/api/v3", timeout=30.0) as client:
        resp = client.get(f"/{kind}/{indicator}", headers={"x-apikey": key})
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    return {
        "indicator": indicator,
        "source": "virustotal",
        "malicious_detections": malicious,
        "classification": "malicious" if malicious > 0 else "clean",
        "stats": stats,
    }


@tool(name="vt_enrich", description="Look up VirusTotal reputation for an IP, domain, or hash")
async def vt_enrich_tool(indicator: str) -> str:
    """Tool wrapper: returns the enrichment as a JSON string."""
    return as_json(vt_enrich(indicator))


@dataclass(frozen=True)
class VirusTotalIntel:
    """A :class:`~tulip.security.SecurityContext` ``ThreatIntelSource`` via VirusTotal."""

    async def enrich(self, indicator: str) -> dict[str, Any]:
        return vt_enrich(indicator)


def virustotal_adapter() -> ToolAdapter:
    return ToolAdapter(name="virustotal", vendor="VirusTotal threat intel", _tools=[vt_enrich_tool])


__all__ = ["VirusTotalIntel", "virustotal_adapter", "vt_enrich", "vt_enrich_tool"]
