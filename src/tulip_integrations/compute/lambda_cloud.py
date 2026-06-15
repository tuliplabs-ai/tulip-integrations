# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Lambda Cloud GPU timing probe — the co-located fingerprint lifecycle.

Launches a Lambda Cloud GPU instance, polls the result sink the probe uploads
its feature JSON to, then terminates the instance. Uses ``httpx`` (a core
dependency) — no extra runtime dep. The feature vector feeds core
:func:`tulip.security.fingerprint_to_finding`.

With ``LAMBDA_API_KEY`` (+ ``LAMBDA_PROBE_RESULT_URL``) set the live lifecycle
runs; with none set it returns the deterministic offline sample.

UNVERIFIED LIVE PATH: written to Lambda's documented API shape, not run against
a real account. Only the offline sample path is exercised in CI.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from typing import Any

from tulip.security import FEATURE_KEYS

_SAMPLE: dict[str, float] = {"ttft_ms_p50": 38.2, "itl_ms_mean": 11.4, "itl_cv": 0.07, "tps_mean": 87.6}


def _select(raw: Mapping[str, Any]) -> dict[str, float]:
    """Keep only the known feature keys, coerced to float."""
    return {k: float(raw[k]) for k in FEATURE_KEYS if k in raw}


def lambda_probe(endpoint: str) -> dict[str, float]:
    """Launch a Lambda GPU instance, poll the probe result, terminate.

    Offline (no ``LAMBDA_API_KEY``) returns the deterministic sample vector.
    """
    if not os.environ.get("LAMBDA_API_KEY"):
        return dict(_SAMPLE)
    import httpx

    key = os.environ["LAMBDA_API_KEY"]
    region = os.environ.get("LAMBDA_REGION", "us-east-1")
    with httpx.Client(
        base_url="https://cloud.lambdalabs.com/api/v1",
        headers={"Authorization": f"Bearer {key}"},
        timeout=60.0,
    ) as client:
        launched = client.post(
            "/instance-operations/launch",
            json={
                "instance_type_name": "gpu_1x_h100_pcie",
                "name": "tulip-timing-probe",
                "region_name": region,
            },
        )
        instance_id = launched.json()["data"]["instance_ids"][0]
        try:
            return _poll_result(endpoint)
        finally:
            client.post("/instance-operations/terminate", json={"instance_ids": [instance_id]})


def _poll_result(endpoint: str, attempts: int = 30, delay_s: float = 10.0) -> dict[str, float]:
    """Poll the result sink the probe uploads its feature JSON to."""
    import httpx

    result_url = os.environ.get("LAMBDA_PROBE_RESULT_URL")
    if not result_url:
        msg = "set LAMBDA_PROBE_RESULT_URL to where the probe uploads its feature JSON"
        raise RuntimeError(msg)
    for _ in range(attempts):
        resp = httpx.get(result_url, params={"endpoint": endpoint}, timeout=30.0)
        if resp.status_code == 200:
            return _select(resp.json())
        time.sleep(delay_s)
    msg = "probe result not available within the polling window"
    raise TimeoutError(msg)


__all__ = ["lambda_probe"]
