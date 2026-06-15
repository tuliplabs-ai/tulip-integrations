# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""Wiz AI-SPM integration — agentic reasoning over your AI security posture.

Wiz discovers *what AI exists in your cloud* (the AI-BOM) and the posture
issues around it. This integration brings that into Tulip so an agent can
**reason over it and emit grounded findings** — the complementary half: Wiz
finds the attack surface; the Tulip agent investigates it, and every Wiz issue
becomes a typed, taxonomy-tagged :class:`~tulip.security.Finding` (grounded in
Wiz's own evidence) instead of an opaque alert.

- :func:`wiz_inventory` — the AI-BOM (models, endpoints, MCP servers, AI
  services) and their exposure.
- :func:`wiz_issues` — posture issues, optionally filtered by severity.
- :func:`wiz_to_findings` — ingest issues → core ``ground_finding`` →
  typed Findings.

With ``WIZ_API_ENDPOINT`` + ``WIZ_CLIENT_ID`` + ``WIZ_CLIENT_SECRET`` set it
authenticates (OAuth2 client-credentials) and queries the Wiz GraphQL API;
with none set it returns a deterministic, benign offline sample so it runs in
CI with no credentials.

LIVE PATH: exercised against a mocked HTTP transport in
``tests/test_live_paths.py`` (OAuth2 + GraphQL request shape + response parsing
verified); Wiz has no free tier, so not run against a real tenant — adjust
fields per your Wiz deployment.
"""

from __future__ import annotations

from typing import cast

from tulip.reasoning.gsar import Partition
from tulip.security import (
    GroundedFinding,
    Indicator,
    IndicatorType,
    OwaspASI,
    OwaspLLM,
    Severity,
    TaxonomyTag,
    ToolAdapter,
    as_json,
    env,
    ground_finding,
    tool_match,
)
from tulip.tools import tool

# Map Wiz severity strings → Tulip severity bands.
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
}

# Benign, invented offline AI-BOM + issues. Hosts use RFC 5737 doc ranges.
_OFFLINE_INVENTORY: list[dict[str, object]] = [
    {"type": "model-endpoint", "name": "prod-llm-gateway", "provider": "self-hosted vLLM", "exposure": "public"},
    {"type": "mcp-server", "name": "internal-tools-mcp", "provider": "tulip", "exposure": "private"},
    {"type": "ai-service", "name": "bedrock-claude", "provider": "aws-bedrock", "exposure": "vpc"},
]

_OFFLINE_ISSUES: list[dict[str, object]] = [
    {
        "id": "wiz-AI-001",
        "severity": "CRITICAL",
        "title": "Publicly exposed model endpoint without authentication",
        "resource": "prod-llm-gateway",
        "evidence": "endpoint reachable from 0.0.0.0/0 on :8000 with no API key",
        "category": "exposure",
    },
    {
        "id": "wiz-AI-002",
        "severity": "HIGH",
        "title": "Over-permissive IAM role attached to AI training job",
        "resource": "sagemaker-train-role",
        "evidence": "role grants s3:* on all buckets; far exceeds job scope",
        "category": "privilege",
    },
    {
        "id": "wiz-AI-003",
        "severity": "MEDIUM",
        "title": "Model artifact bucket without encryption at rest",
        "resource": "models-artifacts-bucket",
        "evidence": "GetBucketEncryption returns no SSE configuration",
        "category": "data",
    },
]

# Issue category → a representative threat-taxonomy tag.
_TAG: dict[str, TaxonomyTag] = {
    "exposure": OwaspLLM.SENSITIVE_INFORMATION_DISCLOSURE,
    "privilege": OwaspASI.IDENTITY_AND_PRIVILEGE_ABUSE,
    "data": OwaspASI.AGENTIC_SUPPLY_CHAIN,
}


def wiz_inventory() -> dict[str, object]:
    """Return the AI-BOM — the AI assets Wiz discovered in the environment."""
    if _wiz_creds():
        return _wiz_graphql("inventory")
    return {"source": "offline-sample", "count": len(_OFFLINE_INVENTORY), "assets": _OFFLINE_INVENTORY}


def wiz_issues(severity: str | None = None) -> dict[str, object]:
    """Return Wiz posture issues, optionally filtered to a minimum severity band."""
    if _wiz_creds():
        return _wiz_graphql("issues", severity)
    issues = _OFFLINE_ISSUES
    if severity:
        floor = _SEV.get(severity.upper(), Severity.INFO)
        from tulip.security import severity_at_least

        issues = [i for i in issues if severity_at_least(_SEV.get(str(i["severity"]), Severity.INFO), floor)]
    return {"source": "offline-sample", "count": len(issues), "issues": issues}


def wiz_to_findings(severity: str | None = None) -> list[GroundedFinding]:
    """Ingest Wiz issues and ground each into a typed :class:`Finding`.

    A Wiz issue is a scanner observation with its own evidence, so it grounds
    to a Finding (tagged to a threat catalogue) — turning opaque AI-SPM alerts
    into the same typed, evidence-cited findings the rest of the SDK emits.
    """
    out: list[GroundedFinding] = []
    issues = cast("list[dict[str, object]]", wiz_issues(severity).get("issues", []))
    for issue in issues:
        sev = _SEV.get(str(issue["severity"]), Severity.INFO)
        ref = f"tool:wiz_issues:{issue['id']}"
        partition = Partition(grounded=[tool_match(str(issue["evidence"]), ref)])
        out.append(
            ground_finding(
                title=str(issue["title"]),
                description=f"Wiz AI-SPM issue {issue['id']} on {issue['resource']}.",
                severity=sev,
                asset=str(issue["resource"]),
                remediation="Review the Wiz issue and remediate per its guidance.",
                partition=partition,
                indicators=[Indicator(type=IndicatorType.HOST, value=str(issue["resource"]))],
                taxonomy=[_TAG.get(str(issue.get("category")), OwaspASI.AGENTIC_SUPPLY_CHAIN)],
            )
        )
    return out


def _wiz_creds() -> bool:
    return bool(env("WIZ_API_ENDPOINT") and env("WIZ_CLIENT_ID") and env("WIZ_CLIENT_SECRET"))


def _wiz_graphql(kind: str, severity: str | None = None) -> dict[str, object]:
    """Authenticate (OAuth2 client-credentials) and query the Wiz GraphQL API."""
    import httpx

    endpoint = env("WIZ_API_ENDPOINT") or ""
    token_url = env("WIZ_AUTH_URL") or "https://auth.app.wiz.io/oauth/token"
    with httpx.Client(timeout=30.0) as client:
        auth = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": env("WIZ_CLIENT_ID"),
                "client_secret": env("WIZ_CLIENT_SECRET"),
                "audience": "wiz-api",
            },
        )
        auth.raise_for_status()
        token = auth.json()["access_token"]
        query = _INVENTORY_QUERY if kind == "inventory" else _ISSUES_QUERY
        resp = client.post(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "variables": {"severity": severity}},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
    return {"source": "wiz", **data}


_INVENTORY_QUERY = "query { aiInventory { type name provider exposure } }"
_ISSUES_QUERY = "query($severity: String) { issues(severity: $severity) { id severity title resource evidence category } }"


@tool(name="wiz_inventory", description="List the AI assets (AI-BOM) Wiz discovered in the cloud")
async def wiz_inventory_tool() -> str:
    """Tool wrapper: returns the AI-BOM as a JSON string."""
    return as_json(wiz_inventory())


@tool(name="wiz_issues", description="List Wiz AI-SPM posture issues, optionally by min severity")
async def wiz_issues_tool(severity: str = "") -> str:
    """Tool wrapper: returns Wiz issues as a JSON string."""
    return as_json(wiz_issues(severity or None))


def wiz_adapter() -> ToolAdapter:
    """The :class:`~tulip.security.SecurityAdapter` for the Wiz integration."""
    return ToolAdapter(name="wiz", vendor="Wiz AI-SPM", _tools=[wiz_inventory_tool, wiz_issues_tool])


__all__ = [
    "wiz_adapter",
    "wiz_inventory",
    "wiz_inventory_tool",
    "wiz_issues",
    "wiz_issues_tool",
    "wiz_to_findings",
]
