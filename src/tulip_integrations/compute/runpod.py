# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""RunPod GPU-cloud timing probe — the real co-located fingerprint lifecycle.

Inference fingerprinting can measure *where the hardware is* from a co-located
probe. This provisions a RunPod GPU pod, runs the probe image against the target
endpoint, collects the timing feature vector, and tears the pod down. The vector
feeds core :func:`tulip.security.fingerprint_to_finding` for a grounded verdict.

With ``RUNPOD_API_KEY`` set the live lifecycle runs (needs the ``runpod`` extra:
``pip install tulip-integrations[compute-runpod]``); with none set it returns the
deterministic offline sample so it runs in CI with no credentials.

UNVERIFIED LIVE PATH: the lifecycle is real but depends on a probe container
image (``RUNPOD_PROBE_IMAGE``, default ``tuliplabs/timing-probe:latest``) that
you supply. Only the offline sample path is exercised in CI.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from tulip.security import FEATURE_KEYS

_SAMPLE: dict[str, float] = {
    "ttft_ms_p50": 38.2,
    "itl_ms_mean": 11.4,
    "itl_cv": 0.07,
    "tps_mean": 87.6,
}


def _select(raw: Mapping[str, Any]) -> dict[str, float]:
    """Keep only the known feature keys, coerced to float."""
    return {k: float(raw[k]) for k in FEATURE_KEYS if k in raw}


def runpod_probe(endpoint: str) -> dict[str, float]:
    """Provision a RunPod GPU pod, run the probe, collect features, tear down.

    Offline (no ``RUNPOD_API_KEY``) returns the deterministic sample vector.
    """
    if not os.environ.get("RUNPOD_API_KEY"):
        return dict(_SAMPLE)
    import runpod  # type: ignore[import-not-found]

    runpod.api_key = os.environ["RUNPOD_API_KEY"]
    image = os.environ.get("RUNPOD_PROBE_IMAGE", "tuliplabs/timing-probe:latest")
    pod = runpod.create_pod(
        name="tulip-timing-probe",
        image_name=image,
        gpu_type_id="NVIDIA H100",
        env={"TARGET_ENDPOINT": endpoint},
    )
    try:
        out = runpod.wait_for_output(pod["id"])
        feats = out.get("features", out) if isinstance(out, dict) else {}
        return _select(feats)
    finally:
        runpod.terminate_pod(pod["id"])


__all__ = ["runpod_probe"]
