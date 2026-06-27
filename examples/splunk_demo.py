#!/usr/bin/env python3
# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Offline demo: wire the Splunk integration into the core security toolset.

    python examples/splunk_demo.py

Runs with no credentials (offline sample) and no model — it shows the
explicit-import + ``security_toolset(extra=...)`` wiring that the
community-package model prescribes.
"""

from __future__ import annotations

from tulip.security import security_toolset

from tulip_integrations.playbooks import splunk_threat_hunt
from tulip_integrations.siem.splunk import splunk_adapter, splunk_search


def main() -> int:
    print("== Splunk adapter (offline sample) ==")
    result = splunk_search("powershell", earliest="-6h")
    print(f"  source={result['source']}  matched {result['count']} event(s)")

    print("\n== Wired into the core toolset via extra= ==")
    tools = security_toolset(siem=False, extra=splunk_adapter().tools())
    print("  toolset:", [t.name for t in tools])

    print("\n== Community playbook ==")
    pb = splunk_threat_hunt()
    print(f"  {pb.id}: " + " -> ".join(s.id for s in pb.steps))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
