# Contributing an integration

The repo is organised **by security domain**, not by vendor:

```
src/tulip_integrations/
  siem/        # Splunk, Elastic, …        -> SecurityContext.logs
  edr/         # CrowdStrike, …            -> SecurityContext.endpoint
  identity/    # Okta, Entra, …            -> SecurityContext.identity
  cloud/       # AWS, Azure, GCP, …        -> SecurityContext.cloud
  threat_intel/# VirusTotal, …             -> SecurityContext.threat_intel
  vuln/        # Wiz, Tenable, …
  ticketing/   # Jira, ServiceNow, …
  compute/     # RunPod, Lambda (GPU probes)
```

A vendor module does two things: ships agent **tools** (the core
[`SecurityAdapter`](https://github.com/tuliplabs-ai/sdk-python) contract) **and**
— where the domain has a port — a **provider class** that plugs into the core
`SecurityContext` so investigation code stays vendor-agnostic. Copy
`tulip_integrations/siem/splunk.py` (logs) or `edr/crowdstrike.py` (endpoint) as
the template.

## Add a vendor integration

1. **New module** `tulip_integrations/<domain>/<vendor>.py`.
2. **A pure function** per capability: call the vendor API on the live path
   (credentials from the environment via `tulip.security.env(...)`) and return a
   deterministic, benign **offline sample** when no credentials are set — same
   return shape on both paths. Delegate the offline path to the matching core
   reference (`query_siem`, `fetch_host_timeline`, `enrich_indicator`, …) when one
   exists, so samples stay consistent.
3. **An `async @tool`** wrapper per action that returns `tulip.security.as_json(...)`.
4. **A `*_adapter()` factory** returning a `tulip.security.ToolAdapter`
   (`name`, `vendor`, `_tools=[…]`).
5. **A provider class** (frozen dataclass) implementing the domain's
   `SecurityContext` port — `LogSource.search`, `EndpointSource.get_host/detections/isolate`,
   `IdentitySource.get_user/risk/signins/disable`, `CloudSource.describe/events`,
   `ThreatIntelSource.enrich`. This is what lets users write
   `SecurityContext(endpoint=CrowdStrikeEndpoint())`. (Domains without a port —
   `vuln`, `ticketing` — ship tools + an adapter only.)
6. **(If it asserts about an asset)** build a GSAR partition with
   `tulip.security.tool_match` / `inference_claim` and route it through
   `tulip.security.ground_finding`, so an ungrounded result abstains.
7. **An extra** in `pyproject.toml` named `<domain>-<vendor>` (e.g.
   `edr-crowdstrike`) if the live path needs a vendor SDK. The offline path must
   need nothing beyond core (httpx is a core dep).
8. **Re-export** from `tulip_integrations/<domain>/__init__.py`.

### Worked example (a `SecurityContext` provider)

```python
from dataclasses import dataclass
from tulip.security import as_json, env, fetch_host_timeline
from tulip.tools import tool

def cs_host_timeline(host: str, window: str = "24h") -> dict:
    url, token = env("CROWDSTRIKE_URL"), env("CROWDSTRIKE_TOKEN")
    if url and token:
        ...                                  # live Falcon call
    out = fetch_host_timeline(host, window=window)   # offline reference
    out["source"] = "offline-sample"
    return out

@tool(name="cs_host_timeline", description="Pull a host's EDR timeline from CrowdStrike")
async def cs_host_tool(host: str, window: str = "24h") -> str:
    return as_json(cs_host_timeline(host, window=window))

@dataclass(frozen=True)
class CrowdStrikeEndpoint:                  # implements SecurityContext EndpointSource
    async def get_host(self, host: str, *, window: str = "24h") -> dict:
        return cs_host_timeline(host, window=window)
    async def detections(self, host=None) -> dict: ...
    async def isolate(self, host_id: str) -> dict: ...
```

## Conformance — required

Every adapter must pass the core conformance kit; every provider must satisfy
its port:

```python
from tulip.security import EndpointSource
from tulip.security.testing import assert_adapter_conformance
from tulip_integrations.edr.crowdstrike import CrowdStrikeEndpoint, crowdstrike_adapter

def test_conforms():
    assert_adapter_conformance(crowdstrike_adapter())
    assert isinstance(CrowdStrikeEndpoint(), EndpointSource)   # plugs into SecurityContext
```

## Add a community playbook

Drop a `Playbook` factory in `tulip_integrations/security/playbooks.py` (or a
YAML loaded with `tulip.playbooks.load_playbook`); reference your integration's
tool names plus any core bundled tools in `expected_tools`.

## Rules

- **One-way dependency.** Import from `tulip` (core); never make core depend on
  this package.
- **Offline by default.** No test may require credentials or network; CI runs
  fully offline.
- **Honesty.** Label any unverified live vendor path; keep it BYO-credentials.
- **Back-compat.** If you move a module, leave a re-export shim at the old path.
