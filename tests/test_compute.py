# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the compute (GPU-cloud) timing-probe integrations (offline)."""

from __future__ import annotations

from tulip.security import FEATURE_KEYS, is_finding

from tulip_integrations.compute import (
    dispatch_timing_probe,
    lambda_probe,
    probe_to_finding,
    runpod_probe,
)


def test_runpod_offline_sample_shape() -> None:
    feats = runpod_probe("203.0.113.10:443")
    assert set(feats) >= set(FEATURE_KEYS)


def test_lambda_offline_sample_shape() -> None:
    feats = lambda_probe("203.0.113.10:443")
    assert set(feats) >= set(FEATURE_KEYS)


def test_dispatch_routes_both_providers() -> None:
    assert dispatch_timing_probe("x:443", "runpod")
    assert dispatch_timing_probe("x:443", "lambda")


def test_probe_grounds_into_a_fingerprint_finding() -> None:
    # Full-coverage sample → ships a grounded fingerprint finding via core.
    result = probe_to_finding("203.0.113.10:443")
    assert is_finding(result)
    assert result.verdict.model
