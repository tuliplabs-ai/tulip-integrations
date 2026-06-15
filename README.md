# tulip-integrations

**Community security integrations for the [Tulip](https://tulipagents.ai/) agentic-AI security SDK.**

Vendor templates (SIEM · EDR · threat-intel · cloud posture) and community
playbooks that plug into the core [`tulip-agents`](https://github.com/tuliplabs-ai/sdk-python)
SDK. This is the **community layer** in a LangChain-style split:

| Layer | Package | Role |
|---|---|---|
| **core** | `tulip-agents` (import `tulip`) | the agentic engine + security **contracts** (`Finding`, `ground_finding`, `SecurityAdapter`, the conformance kit, GSAR) + bundled reference/offline adapters |
| **community** | `tulip-integrations` (import `tulip_integrations`) | maintained, vendor-specific integration **templates** + community playbooks |

The dependency is **one-way**: integrations import the core contracts; core
never imports this package.

## Install

```bash
pip install tulip-agents            # the core SDK
pip install tulip-integrations      # this package (+ any per-vendor extras)
pip install "tulip-integrations[siem-splunk]"
```

## Use — explicit import + `security_toolset(extra=…)`

Discovery is explicit (the LangChain model — no entry-point magic). Import the
adapter you want and merge its tools into the core toolset:

```python
from tulip.agent import Agent
from tulip.security import security_toolset
from tulip_integrations.security.splunk import splunk_siem_tool

agent = Agent(
    model="anthropic:claude-sonnet-4-6",
    tools=security_toolset(siem=False, extra=[splunk_siem_tool]),
    system_prompt="You are a SOC analyst. Cite the evidence behind every verdict.",
)
```

Every adapter follows the core conventions: bring-your-own credentials from the
environment, a deterministic **offline sample** when none are set (so it runs in
CI), JSON-returning `@tool`s, and findings routed through GSAR `ground_finding`
so an ungrounded result abstains.

## What's here

- `tulip_integrations/security/splunk.py` — Splunk/Elastic SIEM (the reference
  template; `SPLUNK_URL` + `SPLUNK_TOKEN`, offline sample otherwise).
- `tulip_integrations/security/wiz.py` — **Wiz AI-SPM**: the AI-BOM + posture
  issues, with `wiz_to_findings()` grounding each Wiz issue into a typed
  `Finding`. The on-positioning marquee — agentic reasoning *over* your AI
  security posture (`WIZ_API_ENDPOINT` + `WIZ_CLIENT_ID` + `WIZ_CLIENT_SECRET`,
  offline sample otherwise).
- `tulip_integrations/security/playbooks.py` — community playbooks
  (`splunk_threat_hunt`, `ai_spm_review`).

More vendors (CrowdStrike/Defender EDR, VirusTotal/GreyNoise intel, Wiz/Prisma
posture, …) are added the same way — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Develop

```bash
git clone https://github.com/tuliplabs-ai/tulip-integrations.git
cd tulip-integrations
pip install -e ../tulip-agents     # core (or `pip install tulip-agents`)
pip install -e ".[dev]"
pytest                              # offline, no credentials
```
