# tulip-integrations

**Vendor security integrations for [Tulip](https://tulipagents.ai/) — the safest way to build agentic AI.**

[Tulip](https://github.com/tuliplabs-ai/sdk-python) is a full-stack, open-source
agent SDK where control is native: the router picks the shape, GSAR grounds every
claim, and the admission gate guards every consequential action. **AI security is
its flagship proof domain** — the place where that control is most obviously worth
paying for. This package is the **vendor security adapters** for that track: the
maintained, vendor-specific integrations that the core SDK's offline reference
adapters stand in for.

Vendor templates — **SIEM · EDR · identity · threat-intel · vuln/posture · GPU
compute** — plus community playbooks that plug into the core
[`tulip-agents`](https://github.com/tuliplabs-ai/sdk-python) SDK. This is the
**community layer** in a core + community package split:

| Layer | Package | Role |
|---|---|---|
| **core** | `tulip-agents` (import `tulip`) | the agentic engine + security **contracts** (`Evidence`, `ground_finding`, `SecurityAdapter`, `SecurityContext` ports, the conformance kit, GSAR) + bundled reference/offline adapters |
| **community** | `tulip-integrations` (import `tulip_integrations`) | maintained, vendor-specific integration **templates** + community playbooks |

The dependency is **one-way**: integrations import the core contracts; core
never imports this package.

## Install

```bash
pip install tulip-agents            # the core SDK
pip install tulip-integrations      # this package
pip install "tulip-integrations[edr-crowdstrike]"   # + a per-vendor extra
```

Per-vendor extras (each pins a vendor SDK only if the *live* path needs one — the
offline path always runs on core alone):

| Extra | Pulls in |
|---|---|
| `siem-splunk` | — (httpx, a core dep) |
| `vuln-wiz` / `wiz-aispm` | — |
| `edr-crowdstrike` | — |
| `threat-intel-virustotal` | — |
| `identity-okta` / `identity-auth0` | — |
| `compute-runpod` | `runpod>=1.0` |
| `compute-lambda` | — |
| `all` | everything above |
| `dev` | `pytest`, `pytest-asyncio`, `ruff`, `mypy` |

## Use — explicit import + `security_toolset(extra=…)`

Discovery is explicit (no entry-point magic). Import the
adapter you want and merge its tools into the core toolset:

```python
from tulip.agent import Agent
from tulip.security import security_toolset
from tulip_integrations.edr.crowdstrike import crowdstrike_adapter
from tulip_integrations.threat_intel.virustotal import vt_enrich_tool

agent = Agent(
    model="anthropic:claude-sonnet-4-6",
    tools=security_toolset(
        extra=[*crowdstrike_adapter().tools(), vt_enrich_tool],
    ),
    system_prompt="You are a SOC analyst. Cite the evidence behind every verdict.",
)
```

Or wire providers into a vendor-agnostic `SecurityContext` so investigation code
never names a vendor:

```python
from tulip.security import SecurityContext
from tulip_integrations.siem.splunk import SplunkLogs
from tulip_integrations.edr.crowdstrike import CrowdStrikeEndpoint
from tulip_integrations.identity.okta import OktaIdentity

ctx = SecurityContext(
    logs=SplunkLogs(),
    endpoint=CrowdStrikeEndpoint(),
    identity=OktaIdentity(),
)
```

## Conventions every integration follows

- **Bring-your-own credentials** from the environment (read via `tulip.security.env`).
- **Deterministic offline sample** when no credentials are set — same return
  shape on both paths, so the whole suite runs in CI with no secrets or network.
- **JSON-returning `async @tool`s** (`tulip.security.as_json`), plus a
  `*_adapter()` factory returning a core `ToolAdapter`.
- **GSAR grounding**: anything that asserts about an asset routes through
  `ground_finding`, so an **ungrounded result abstains** rather than guessing.
- **Read vs. write** are distinct tools; writes (host isolation, user disable)
  are marked and meant to be gated behind human approval in agentic use. Note
  that the identity **disable** writes (`okta_disable`, `auth0_disable`) are
  currently **simulated offline stubs** — they return a `source: "offline-sample"`
  receipt and do **not** call the provider, so they never actually lock an account
  out. Wire the live Graph/Management-API PATCH before approval-gating them as a
  real enforcement action. (`cs_isolate` does have a live containment path.)
- Where a domain has a core **port**, the vendor also ships a provider class
  (`SplunkLogs`, `CrowdStrikeEndpoint`, `Auth0Identity`/`OktaIdentity`,
  `VirusTotalIntel`) that plugs into `SecurityContext`.

## Integration catalog

| Domain | Vendor | Import (`tulip_integrations…`) | Tools | Env vars (live path) | `SecurityContext` provider |
|---|---|---|---|---|---|
| **SIEM** | Splunk | `siem.splunk` | `splunk_search` | `SPLUNK_URL`, `SPLUNK_TOKEN` | `SplunkLogs` |
| **EDR** | CrowdStrike Falcon | `edr.crowdstrike` | `cs_host_timeline`, `cs_detections`, `cs_isolate` ⚠️*write* | `CROWDSTRIKE_URL`/`FALCON_URL`, `CROWDSTRIKE_TOKEN`/`FALCON_TOKEN` | `CrowdStrikeEndpoint` |
| **Identity** | Okta | `identity.okta` | `okta_get_user`, `okta_risk`, `okta_signins`, `okta_disable` ⚠️*write* | `OKTA_URL`, `OKTA_TOKEN` | `OktaIdentity` |
| **Identity** | Auth0 | `identity.auth0` | `auth0_get_user`, `auth0_risk`, `auth0_signins`, `auth0_disable` ⚠️*write* | `AUTH0_DOMAIN` + `AUTH0_MGMT_TOKEN` (or `AUTH0_CLIENT_ID` + `AUTH0_CLIENT_SECRET`) | `Auth0Identity` |
| **Threat intel** | VirusTotal | `threat_intel.virustotal` | `vt_enrich` | `VT_API_KEY`/`VIRUSTOTAL_API_KEY` | `VirusTotalIntel` |
| **Vuln / AI-SPM** | Wiz | `vuln.wiz` | `wiz_inventory`, `wiz_issues` (+ `wiz_to_findings()`) | `WIZ_API_ENDPOINT`, `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` (opt. `WIZ_AUTH_URL`) | — |
| **Compute** | RunPod | `compute.runpod` | `runpod_probe()` | `RUNPOD_API_KEY` (opt. `RUNPOD_PROBE_IMAGE`) | — |
| **Compute** | Lambda Cloud | `compute.lambda_cloud` | `lambda_probe()` | `LAMBDA_API_KEY` (opt. `LAMBDA_REGION`, `LAMBDA_PROBE_RESULT_URL`) | — |

Tool objects are exported with a `_tool` suffix (`splunk_siem_tool`,
`cs_host_tool`, `cs_detections_tool`, `cs_isolate_tool`, `okta_user_tool`,
`okta_disable_tool`, `auth0_user_tool`, `auth0_disable_tool`, `vt_enrich_tool`,
`wiz_inventory_tool`, `wiz_issues_tool`).

### By domain

**SIEM — Splunk.** SPL search over the export endpoint (the same SPL shape works
against an Elastic-compatible endpoint; only the Splunk adapter ships today);
offline sample otherwise.
```python
from tulip_integrations.siem.splunk import splunk_search
splunk_search("powershell -enc", earliest="-6h", count=50)
```

**EDR — CrowdStrike Falcon.** Host timeline + open detections (read), plus
network-containment (`cs_isolate`, a write — gate it).
```python
from tulip_integrations.edr.crowdstrike import cs_detections, cs_isolate
cs_detections(host="WIN-ABC")          # read
cs_isolate(host_id="abc123")           # write — contains the host
```

**Identity — Okta / Auth0.** User lookup, risk signals, recent sign-ins (read),
and disable/block (write — currently a **simulated** offline receipt, not a live
account lockout). Risk signals on the live path read only the bundled sample
users, so an unknown user grounds to `risk="unknown"` rather than a live risk
query.
```python
from tulip_integrations.identity.okta import okta_get_user, okta_disable
okta_get_user("user@example.com")      # read
okta_disable("user@example.com")       # write — offline stub: returns a receipt, locks nobody out yet
```

**Threat intel — VirusTotal.** Reputation for an IP, domain, or file hash.
```python
from tulip_integrations.threat_intel.virustotal import vt_enrich
vt_enrich("8.8.8.8")
```

**Vuln / AI-SPM — Wiz.** The AI-BOM + posture issues, with `wiz_to_findings()`
grounding each issue into a typed `GroundedFinding` — agentic reasoning *over*
your AI security posture.
```python
from tulip_integrations.vuln.wiz import wiz_issues, wiz_to_findings
wiz_issues(severity="high")
findings = wiz_to_findings(severity="high")   # list[GroundedFinding]
```

**Compute — inference fingerprinting on a co-located GPU.** Provision a GPU,
run a co-located timing probe against an inference endpoint, and ground the
feature vector (TTFT / ITL / TPS) into a `FingerprintFinding` — model, engine,
and hardware class, tagged to MITRE ATLAS (`AML.T0040`, `AML.T0024`). RunPod and
Lambda Cloud are **two separate modules** because they collect the probe's
result two different ways — pick one explicitly:

```python
from tulip_integrations.compute import probe_to_finding
probe_to_finding("https://my-endpoint/v1", provider="runpod")  # or provider="lambda"
```

- **RunPod** (`compute.runpod.runpod_probe`, extra `compute-runpod`) — uses the
  RunPod SDK to spin up a **pod from a container image** (`RUNPOD_PROBE_IMAGE`,
  default `tuliplabs/timing-probe:latest`), waits for the pod's output, parses the
  feature vector, and terminates the pod. The probe *is* the image — you build it.
  Credential: `RUNPOD_API_KEY`.
- **Lambda Cloud** (`compute.lambda_cloud.lambda_probe`, extra `compute-lambda`) —
  launches an instance over `httpx` (no extra SDK), then **polls a result sink**
  the probe uploads its JSON to (`LAMBDA_PROBE_RESULT_URL`), and terminates the
  instance. Lambda has no "wait for output" call, hence the sink. Credentials:
  `LAMBDA_API_KEY` (+ `LAMBDA_REGION`).

> ⚠️ Both compute **live paths are billable** — each spins up an H100-class GPU —
> and both are flagged `UNVERIFIED LIVE PATH` in source (RunPod needs the probe
> image you supply; Lambda needs the `LAMBDA_PROBE_RESULT_URL` sink). With no key
> set each returns the deterministic offline sample. Gate the live path behind
> explicit approval and set provider spend limits.

## Community playbooks

`tulip_integrations.playbooks` ships ready-made `Playbook` factories that
reference these tools:

- `splunk_threat_hunt()` — SIEM-driven hunt
- `ai_spm_review()` — Wiz AI-SPM posture review

```python
from tulip_integrations.playbooks import ai_spm_review
pb = ai_spm_review()
```

## Trying it for free

- **Zero keys (recommended first run):** every adapter returns its **offline
  sample** with no credentials, so `pytest` and `examples/splunk_demo.py` run
  end-to-end for free.
- **Real keys:** the products differ on free access —
  - **Splunk** has a genuine free trial (Cloud 14-day; Enterprise 60-day) plus a
    perpetual **Splunk Free** license; **Elastic** has a 14-day cloud trial.
  - **VirusTotal** has a free community API key (rate-limited).
  - **Okta** and **Auth0** both have free developer tenants.
  - **Wiz** is sales-gated (a "free assessment", no self-serve tier).
  - **CrowdStrike** offers a 15-day Falcon trial.
  - **RunPod** and **Lambda** are pay-as-you-go GPU clouds — the API key is free
    to generate, but running the probe launches a **billable** GPU.

## Develop

```bash
git clone https://github.com/tuliplabs-ai/tulip-integrations.git
cd tulip-integrations
pip install -e ../tulip-agents      # core (or `pip install tulip-agents`)
pip install -e ".[dev]"
pytest                              # offline, no credentials
ruff check src tests examples       # lint
mypy src/tulip_integrations         # types (strict)
```

With [hatch](https://hatch.pypa.io/): `hatch run check` runs lint + types +
tests in one shot.

## Contributing

The repo is organised **by security domain**, not by vendor — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the module template, the
`SecurityContext` provider contract, and the required conformance test. Rules of
the road: one-way dependency on core, offline-by-default (no test needs
credentials or network), label any unverified live path, and leave a re-export
shim if you move a module.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
