#!/usr/bin/env python3
"""Populate TrustChain Platform with realistic demo data for YC video.

Creates ~260 agents (with sub-agents) and ~1500 licenses.
Run once before recording the demo.

Usage:
    python demo/populate_demo_data.py
"""

import random
import string
from datetime import datetime, timedelta, timezone

import requests

BASE = "https://app.trust-chain.ai"
AUTH = ("admin", "trustchain2024#")
API_KEY = "tc-dev-key-12345"
HEADERS = {"X-Platform-API-Key": API_KEY}

# ── Agent templates ──
AGENT_DOMAINS = {
    "finance": {
        "prefixes": [
            "wire-transfer",
            "balance-check",
            "fraud-detect",
            "aml-scan",
            "payment-proc",
            "invoice-gen",
            "tax-calc",
            "audit-trail",
            "risk-score",
            "compliance-check",
            "kyc-verify",
            "ledger-sync",
        ],
        "capabilities": [
            "bank_transfer",
            "balance_query",
            "fraud_detection",
            "aml_screening",
            "payment_processing",
            "invoice_generation",
        ],
        "sub_count": (1, 4),
    },
    "healthcare": {
        "prefixes": [
            "hipaa-audit",
            "ehr-extract",
            "prescription-verify",
            "patient-match",
            "claims-proc",
            "dicom-analyze",
            "lab-results",
            "med-summary",
            "consent-mgr",
        ],
        "capabilities": [
            "ehr_access",
            "hipaa_audit",
            "prescription_verify",
            "patient_matching",
            "claims_processing",
        ],
        "sub_count": (1, 3),
    },
    "devops": {
        "prefixes": [
            "deploy-agent",
            "ci-runner",
            "infra-scan",
            "k8s-mgr",
            "log-analyzer",
            "incident-resp",
            "config-mgr",
            "secret-rotate",
            "perf-monitor",
            "chaos-test",
        ],
        "capabilities": [
            "code_execution",
            "deploy",
            "infrastructure_scan",
            "log_analysis",
            "secret_management",
        ],
        "sub_count": (2, 5),
    },
    "legal": {
        "prefixes": [
            "contract-review",
            "clause-extract",
            "compliance-scan",
            "nda-gen",
            "ip-search",
            "reg-track",
            "e-sign",
        ],
        "capabilities": [
            "document_analysis",
            "contract_review",
            "compliance_check",
            "e_signature",
            "regulatory_tracking",
        ],
        "sub_count": (0, 2),
    },
    "sales": {
        "prefixes": [
            "lead-score",
            "crm-sync",
            "email-outreach",
            "demo-book",
            "proposal-gen",
            "forecast-calc",
            "deal-track",
        ],
        "capabilities": [
            "crm_access",
            "email_send",
            "calendar_book",
            "document_generation",
            "analytics",
        ],
        "sub_count": (1, 3),
    },
    "data": {
        "prefixes": [
            "etl-pipeline",
            "data-quality",
            "schema-migrate",
            "report-gen",
            "dashboard-sync",
            "warehouse-opt",
            "ml-inference",
            "feature-store",
        ],
        "capabilities": [
            "db_query",
            "data_transform",
            "ml_inference",
            "report_generation",
            "schema_management",
        ],
        "sub_count": (1, 4),
    },
    "security": {
        "prefixes": [
            "vuln-scan",
            "pen-test",
            "siem-alert",
            "threat-intel",
            "access-review",
            "cert-rotate",
            "waf-config",
        ],
        "capabilities": [
            "vulnerability_scan",
            "threat_detection",
            "access_management",
            "certificate_management",
        ],
        "sub_count": (1, 3),
    },
    "support": {
        "prefixes": [
            "ticket-triage",
            "kb-search",
            "escalation-mgr",
            "sentiment-analyze",
            "response-draft",
            "sla-monitor",
        ],
        "capabilities": [
            "ticket_management",
            "knowledge_base",
            "email_send",
            "sentiment_analysis",
            "sla_monitoring",
        ],
        "sub_count": (0, 2),
    },
}

# ── License templates ──
ORG_TEMPLATES = [
    # (prefix, industry, count_multiplier)
    ("acme", "Manufacturing", 3),
    ("globex", "Technology", 5),
    ("initech", "Software", 4),
    ("aperture", "Research", 2),
    ("wayne", "Defense", 2),
    ("stark", "Energy", 3),
    ("umbrella", "Biotech", 2),
    ("cyberdyne", "AI/ML", 4),
    ("weyland", "Aerospace", 2),
    ("oscorp", "Pharmaceuticals", 3),
    ("lexcorp", "Media", 2),
    ("tyrell", "Robotics", 3),
    ("soylent", "Food Tech", 1),
    ("massive", "Gaming", 2),
    ("abstergo", "Consulting", 3),
    ("vault-tec", "Infrastructure", 2),
    ("momcorp", "Conglomerate", 4),
    ("buy-n-large", "Retail", 3),
    ("genco", "Logistics", 2),
    ("sterling", "Finance", 5),
    ("hooli", "Cloud", 4),
    ("piedpiper", "Compression", 1),
    ("raviga", "VC", 2),
    ("endframe", "Streaming", 2),
    ("gavin-b", "Enterprise", 3),
]

TIERS = ["pro", "enterprise"]
FEATURES_BY_TIER = {
    "pro": ["streaming", "policy", "tsa", "compliance"],
    "enterprise": [
        "streaming",
        "policy",
        "redis_ha",
        "graph",
        "tsa",
        "compliance",
        "analytics",
        "kms",
        "airgap",
        "factseal",
    ],
}

COUNTRIES = [
    "US",
    "UK",
    "DE",
    "JP",
    "SG",
    "AU",
    "CA",
    "FR",
    "NL",
    "KR",
    "IL",
    "CH",
    "SE",
    "NO",
    "BR",
    "IN",
    "AE",
]


def rand_hash():
    return "".join(random.choices(string.hexdigits.lower(), k=64))


def register_agent(agent_id, capabilities, parent=None, validity_hours=None):
    """Register an agent via API."""
    payload = {
        "agent_id": agent_id,
        "model_hash": rand_hash(),
        "prompt_hash": rand_hash(),
        "tool_versions": {"trustchain": "2.3.3"},
        "capabilities": capabilities,
        "validity_hours": validity_hours or random.choice([1, 2, 4, 8, 24]),
    }
    if parent:
        payload["parent_agent_id"] = parent
    try:
        r = requests.post(
            f"{BASE}/api/agents/register",
            json=payload,
            headers=HEADERS,
            auth=AUTH,
            timeout=15,
        )
        if r.status_code == 409:
            return None  # already exists
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  ⚠ {agent_id}: {e}")
        return None


def issue_license(org_id, org_name, tier, max_seats, features, contact_email):
    """Issue a license via API."""
    expires = (
        datetime.now(timezone.utc) + timedelta(days=random.randint(90, 730))
    ).isoformat()
    payload = {
        "org_id": org_id,
        "org_name": org_name,
        "tier": tier,
        "max_seats": max_seats,
        "features": features,
        "expires": expires,
        "contact_email": contact_email,
        "notes": f"Auto-provisioned for {org_name}",
    }
    try:
        r = requests.post(
            f"{BASE}/api/licenses",
            json=payload,
            headers=HEADERS,
            auth=AUTH,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  ⚠ license {org_id}: {e}")
        return None


def main():
    print("═" * 60)
    print("  TrustChain Platform — Demo Data Population")
    print("═" * 60)

    # ── Check connectivity ──
    r = requests.get(f"{BASE}/api/agents/stats", headers=HEADERS, auth=AUTH, timeout=10)
    stats = r.json()
    print(f"\n  Current: {stats['total_agents']} agents, checking licenses...")

    r2 = requests.get(
        f"{BASE}/api/licenses/stats", headers=HEADERS, auth=AUTH, timeout=10
    )
    lic_stats = r2.json()
    print(f"  Current: {lic_stats.get('total', 0)} licenses\n")

    # ── Phase 1: Agents ──
    print("━" * 60)
    print("  Phase 1: Registering agents...")
    print("━" * 60)

    agent_count = 0
    sub_agent_count = 0

    for _domain, config in AGENT_DOMAINS.items():
        for prefix in config["prefixes"]:
            # Register 2-3 variants per prefix (different orgs/regions)
            for variant in range(random.randint(2, 3)):
                region = random.choice(COUNTRIES)
                agent_id = f"{prefix}-{region.lower()}-{variant + 1:02d}"
                caps = random.sample(
                    config["capabilities"], min(3, len(config["capabilities"]))
                )

                result = register_agent(agent_id, caps)
                if result:
                    agent_count += 1
                    if agent_count % 25 == 0:
                        print(f"  ✓ {agent_count} agents registered...")

                    # Sub-agents
                    lo, hi = config["sub_count"]
                    n_subs = random.randint(lo, hi)
                    for s in range(n_subs):
                        sub_id = f"{agent_id}-sub-{s + 1:02d}"
                        sub_caps = random.sample(caps, min(2, len(caps)))
                        sub_result = register_agent(sub_id, sub_caps, parent=agent_id)
                        if sub_result:
                            sub_agent_count += 1

    print(f"\n  ✅ Agents: {agent_count} registered, {sub_agent_count} sub-agents")

    # ── Phase 2: Licenses ──
    print("\n" + "━" * 60)
    print("  Phase 2: Issuing licenses...")
    print("━" * 60)

    license_count = 0

    for org_prefix, industry, multiplier in ORG_TEMPLATES:
        for i in range(multiplier):
            for region in random.sample(COUNTRIES, min(multiplier * 4, len(COUNTRIES))):
                org_id = f"{org_prefix}-{industry.lower().replace('/', '-')}-{region.lower()}-{i + 1:03d}"
                org_name = f"{org_prefix.title()} {industry} ({region})"
                tier = random.choice(TIERS)
                max_seats = random.choice([5, 10, 25, 50, 100, 250])
                features = FEATURES_BY_TIER[tier]
                email = f"admin@{org_prefix}-{region.lower()}.com"

                result = issue_license(
                    org_id, org_name, tier, max_seats, features, email
                )
                if result:
                    license_count += 1
                    if license_count % 100 == 0:
                        print(f"  ✓ {license_count} licenses issued...")

    print(f"\n  ✅ Licenses: {license_count} issued")

    # ── Summary ──
    print("\n" + "═" * 60)
    r = requests.get(f"{BASE}/api/agents/stats", headers=HEADERS, auth=AUTH, timeout=10)
    final_stats = r.json()
    r2 = requests.get(
        f"{BASE}/api/licenses/stats", headers=HEADERS, auth=AUTH, timeout=10
    )
    final_lic = r2.json()
    print(
        f"  Final: {final_stats['total_agents']} agents ({final_stats['total_sub_agents']} sub-agents)"
    )
    print(f"  Final: {final_lic.get('total', '?')} licenses")
    print(f"  Merkle root: {final_stats['merkle_root'][:40]}...")
    print("═" * 60)


if __name__ == "__main__":
    main()
