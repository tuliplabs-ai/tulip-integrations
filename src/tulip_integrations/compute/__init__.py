# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Compute integrations — GPU-cloud backends for the inference-fingerprint probe.

These provision GPU hardware to run a co-located timing probe and return the
feature vector that core :func:`tulip.security.fingerprint_to_finding` grounds
into a verdict. Core ships only the credential-free remote-API measurement and
an offline reference dispatch; the real RunPod / Lambda lifecycle lives here.
"""

from __future__ import annotations

from tulip.security import GroundedFinding, fingerprint_to_finding

from tulip_integrations.compute.lambda_cloud import lambda_probe
from tulip_integrations.compute.runpod import runpod_probe


def dispatch_timing_probe(endpoint: str, provider: str = "runpod") -> dict[str, float]:
    """Run a co-located timing probe against ``endpoint`` on a GPU cloud.

    ``provider`` selects the backend — ``"runpod"`` (default) or ``"lambda"``.
    Returns the timing feature vector (offline sample when no credentials).
    """
    if provider == "lambda":
        return lambda_probe(endpoint)
    return runpod_probe(endpoint)


def probe_to_finding(endpoint: str, provider: str = "runpod") -> GroundedFinding:
    """Probe ``endpoint`` on a GPU cloud and ground the fingerprint into a finding."""
    return fingerprint_to_finding(dispatch_timing_probe(endpoint, provider), asset=endpoint)


__all__ = ["dispatch_timing_probe", "lambda_probe", "probe_to_finding", "runpod_probe"]
