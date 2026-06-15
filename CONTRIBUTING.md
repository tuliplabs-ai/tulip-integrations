# Contributing an integration

An integration is a small module that implements the core
[`SecurityAdapter`](https://github.com/tuliplabs-ai/sdk-python) contract and
reuses the core toolkit. Copy `tulip_integrations/security/splunk.py` as the
template.

## Add a vendor adapter

1. **New module** `tulip_integrations/security/<vendor>.py`.
2. **A pure function** that calls the vendor's API on the live path (credentials
   from the environment via `tulip.security.env(...)`) and returns a
   deterministic, benign **offline sample** when no credentials are set — so it
   runs in CI with no network. Keep the same return shape on both paths.
3. **An `async @tool`** wrapper that returns `tulip.security.as_json(...)`.
4. **A `*_adapter()` factory** returning a `tulip.security.ToolAdapter`
   (`name`, `vendor`, `_tools=[…]`).
5. **(If it asserts about an asset)** build a GSAR partition with
   `tulip.security.tool_match` / `inference_claim` and route it through
   `tulip.security.ground_finding`, so an ungrounded result abstains.
6. **An optional extra** in `pyproject.toml` (`<area>-<vendor>`) if the live
   path needs a vendor SDK. The offline path must need nothing beyond core.

## Conformance — required

Every adapter must pass the core conformance kit (the `langchain-tests` analog):

```python
from tulip.security.testing import assert_adapter_conformance, assert_tool_returns_json
from tulip_integrations.security.<vendor> import <vendor>_adapter, <vendor>_tool

def test_conforms():
    assert_adapter_conformance(<vendor>_adapter())

async def test_tool_json():
    await assert_tool_returns_json(<vendor>_tool, "…")   # offline path
```

## Add a community playbook

Drop a `Playbook` factory in `tulip_integrations/security/playbooks.py` (or a
YAML loaded with `tulip.playbooks.load_playbook`). Reference your integration's
tool names plus any core bundled tools in `expected_tools`. See
`splunk_threat_hunt()`.

## Rules

- **One-way dependency.** Import from `tulip` (core); never make core depend on
  this package.
- **Offline by default.** No test may require credentials or network.
- **Honesty.** Label any unverified live vendor path; keep it BYO-credentials.
