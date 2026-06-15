# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Live-path verification for **every** vendor, against a mocked HTTP transport.

The offline fallback is covered elsewhere; this proves the *live* branch — the
exact request each provider sends (URL, method, auth scheme) and that it parses
the vendor's real response shape — without needing any credentials. So all
integrations are exercised end-to-end in CI, including the ones (CrowdStrike,
Wiz) that have no free tier to hit for real.

Vendors with a free tier (VirusTotal, Auth0) are *additionally* hit against the
real API in their own ``test_live_*.py`` (which skip without creds).
"""

from __future__ import annotations

import httpx
import pytest

# Every vendor env var, so each test starts from a known-clean environment even
# when a dev shell has real creds exported.
_VENDOR_ENVS = (
    "AUTH0_MGMT_TOKEN", "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET",
    "OKTA_URL", "OKTA_TOKEN",
    "SPLUNK_URL", "SPLUNK_TOKEN",
    "CROWDSTRIKE_URL", "CROWDSTRIKE_TOKEN", "FALCON_URL", "FALCON_TOKEN",
    "VT_API_KEY", "VIRUSTOTAL_API_KEY",
    "WIZ_API_ENDPOINT", "WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_AUTH_URL",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _VENDOR_ENVS:
        monkeypatch.delenv(var, raising=False)


def _mock_http(monkeypatch: pytest.MonkeyPatch, handler):  # type: ignore[no-untyped-def]
    """Route all httpx traffic (Client + top-level get/post) through MockTransport.

    Returns the list of captured requests for post-hoc assertions.
    """
    captured: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(recording)
    real_client = httpx.Client

    def client_factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    def top_level(method: str):  # type: ignore[no-untyped-def]
        def _call(url, **kw):  # type: ignore[no-untyped-def]
            with real_client(transport=transport) as c:
                return c.request(method, url, **kw)
        return _call

    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(httpx, "get", top_level("GET"))
    monkeypatch.setattr(httpx, "post", top_level("POST"))
    return captured


def test_virustotal_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "vt-dummy")

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.headers["x-apikey"] == "vt-dummy"
        assert req.url.path.endswith("/ip_addresses/8.8.8.8")
        return httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}}
        )

    reqs = _mock_http(monkeypatch, handler)
    from tulip_integrations.threat_intel.virustotal import vt_enrich

    out = vt_enrich("8.8.8.8")
    assert out["source"] == "virustotal"
    assert out["classification"] == "clean"
    assert out["malicious_detections"] == 0
    assert len(reqs) == 1


def test_splunk_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "sp-tok")

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "POST"
        assert req.url.path == "/services/search/jobs/export"
        assert req.headers["authorization"] == "Bearer sp-tok"
        return httpx.Response(200, json={"results": [{"_raw": "winword spawned powershell", "host": "WS-1"}]})

    _mock_http(monkeypatch, handler)
    from tulip_integrations.siem.splunk import splunk_search

    out = splunk_search("powershell")
    assert out["source"] == "splunk"
    assert out["count"] == 1


def test_crowdstrike_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CROWDSTRIKE_URL", "https://api.crowdstrike.example")
    monkeypatch.setenv("CROWDSTRIKE_TOKEN", "cs-tok")

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "Bearer cs-tok"
        if req.method == "GET":
            assert req.url.path == "/devices/entities/devices/v2"
            return httpx.Response(200, json={"resources": [{"device_id": "dev1"}]})
        assert req.url.path == "/devices/entities/devices-actions/v2"
        return httpx.Response(200, json={"resources": []})

    _mock_http(monkeypatch, handler)
    from tulip_integrations.edr.crowdstrike import cs_host_timeline, cs_isolate

    host = cs_host_timeline("dev1")
    assert host["source"] == "crowdstrike"
    contained = cs_isolate("dev1")
    assert contained["source"] == "crowdstrike"
    assert contained["contained"] is True


def test_okta_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OKTA_URL", "https://dev-123.okta.example")
    monkeypatch.setenv("OKTA_TOKEN", "ok-tok")

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.headers["authorization"] == "SSWS ok-tok"
        assert req.url.path.startswith("/api/v1/users/")
        return httpx.Response(200, json={"id": "00u1", "status": "ACTIVE"})

    _mock_http(monkeypatch, handler)
    from tulip_integrations.identity.okta import okta_get_user

    out = okta_get_user("jsmith@example.com")
    assert out["source"] == "okta"
    assert out["data"]["status"] == "ACTIVE"


def test_auth0_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # No AUTH0_MGMT_TOKEN -> exercises the client_credentials grant + Management API.
    monkeypatch.setenv("AUTH0_DOMAIN", "dev.auth0.example")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "sec")

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":
            assert req.method == "POST"
            return httpx.Response(200, json={"access_token": "jwt-123"})
        if req.url.path == "/api/v2/users-by-email":
            assert req.headers["authorization"] == "Bearer jwt-123"
            assert req.url.params["email"] == "a@b.com"
            return httpx.Response(200, json=[{"user_id": "auth0|1", "email": "a@b.com"}])
        raise AssertionError(f"unexpected request: {req.url}")

    reqs = _mock_http(monkeypatch, handler)
    from tulip_integrations.identity.auth0 import auth0_get_user

    out = auth0_get_user("a@b.com")
    assert out["source"] == "auth0"
    assert out["data"][0]["user_id"] == "auth0|1"
    assert {r.url.path for r in reqs} == {"/oauth/token", "/api/v2/users-by-email"}


def test_wiz_live_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WIZ_API_ENDPOINT", "https://api.wiz.example/graphql")
    monkeypatch.setenv("WIZ_CLIENT_ID", "wcid")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "wsec")

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/oauth/token":  # auth.app.wiz.io
            assert req.method == "POST"
            return httpx.Response(200, json={"access_token": "wiz-tok"})
        assert req.url.path == "/graphql"
        assert req.headers["authorization"] == "Bearer wiz-tok"
        return httpx.Response(200, json={"data": {"issues": [{"id": "wiz-AI-001", "severity": "CRITICAL"}]}})

    reqs = _mock_http(monkeypatch, handler)
    from tulip_integrations.vuln.wiz import wiz_issues

    out = wiz_issues()
    assert out["source"] == "wiz"
    assert out["issues"][0]["id"] == "wiz-AI-001"
    assert {r.url.path for r in reqs} == {"/oauth/token", "/graphql"}
