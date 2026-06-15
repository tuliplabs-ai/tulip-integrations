# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Live VirusTotal check — runs only when VT_API_KEY is set (skips in CI).

Verified live on 2026-06-15. Re-run with:
    VT_API_KEY=... pytest tests/test_live_virustotal.py
"""

from __future__ import annotations

import os

import pytest

from tulip_integrations.threat_intel.virustotal import vt_enrich

pytestmark = pytest.mark.skipif(
    not (os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")),
    reason="set VT_API_KEY to run the live VirusTotal check",
)

# EICAR test-file hash — the standard, harmless "known malicious" sample.
_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_live_clean_ip() -> None:
    r = vt_enrich("8.8.8.8")
    assert r["source"] == "virustotal"
    assert r["classification"] == "clean"


def test_live_malicious_hash() -> None:
    r = vt_enrich(_EICAR_SHA256)
    assert r["source"] == "virustotal"
    assert r["malicious_detections"] > 0
