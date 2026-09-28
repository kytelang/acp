# Technical Gap & Implementation Blueprint: Varman (ACP)

This document provides a comprehensive technical gap analysis and actionable engineering blueprint for the **Varman Agent Control Plane (ACP)**. It maps current capabilities against key international standards (**EU AI Act**, **NIST AI RMF**, **ISO/IEC 42001**, and **ISO/IEC 23894**) and outlines the specific modules required to establish Varman as an audit-grade AI control plane.

---

## 1. Governance & Compliance Gap Analysis

| Standard / Framework | Regulatory Requirement | Varman Current State | Gap Assessment | Required Engineering Enhancement |
| :--- | :--- | :--- | :--- | :--- |
| **EU AI Act (Art. 14)** | **Human Oversight & Stop Controls** | Basic `step_up` verdict in Cedar policy; manual CLI kill-switch. | **Partial** | Native operational hooks (Slack, Jira, PagerDuty), short-lived approval tokens, and automated escalation logic. |
| **EU AI Act (Art. 9 & 12)** | **High-Risk Classification & Record-Keeping** | Manual rule definitions; raw payload logging in Merkle trees. | **Critical** | Automated Risk Mapping Engine matching agent activity to EU AI Act High-Risk Annexes; automated Fundamental Rights Impact Assessment (FRIA) exports. |
| **NIST AI RMF (Measure & Govern)** | **Model Evaluation & Continuous Performance Monitoring** | Inline proxy focused on access policies and security limits. | **Critical** | Async evaluation pipeline measuring hallucination rates, toxicity, schema drift, and model degradation alongside Cedar policy enforcement. |
| **ISO/IEC 42001 (Control A.8)** | **AI System Impact & Data Lineage Governance** | Redaction obligations (PII masking) available in policy. | **Partial** | Lineage and provenance tracking for RAG data sources, tool call bindings, and automated ISO-formatted compliance reporting. |
| **Enterprise Ops / SIEM Integration** | **Production Readiness & Zero-Downtime Rollout** | Fail-closed Cedar execution without passive dry-run options. | **High** | Multi-mode deployment engine (`Observe / Audit Mode` $\rightarrow$ `Enforce Mode`) to allow safe policy testing in production pipelines. |

---

## 2. Priority Implementation Engineering Modules

### Module A: Automated Regulatory & Risk Assessment Engine

**Goal:** Dynamically assign an EU AI Act risk tier and NIST AI RMF classification to agent instances based on their tool bindings, access levels, and domain context.

```
       ┌───────────────────────────┐
       │   Agent Context & Tools   │
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │   Risk Mapping Engine     │
       │ (Annex III / ISO 42001)   │
       └─────────────┬─────────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
┌───────────────────┐ ┌───────────────────┐
│ High-Risk System  │ │ Unacceptable Risk │
│  (Trigger FRIA &  │ │  (Auto Fail-Deny  │
│ Strict Log Leases)│ │  Cedar Execution) │
└───────────────────┘ └───────────────────┘
```

#### Implementation Specification
1. Extend the agent registration metadata schema to include business domain parameters.
2. Automatically flag operations touching sensitive domains (e.g., HR resume screening, credit scoring, critical infrastructure control).

```json
{
  "agent_id": "agent-finance-09",
  "compliance_profile": {
    "eu_ai_act_classification": "High-Risk (Annex III - Sec 5b)",
    "iso_42001_controls": ["A.6.2", "A.8.4"],
    "nist_ai_rmf_lifecycle": "Deploy/Measure"
  },
  "risk_triggers": [
    "database:write:credit_scores",
    "mcp:tool:execute_bank_transfer"
  ]
}
```

---

### Module B: Human-in-the-Loop (HITL) Workflow Integration

**Goal:** Expand the Cedar `step_up` verdict beyond CLI flags by integrating real-time operational webhooks.

```
+-----------------------------------------------------------------------------------+
|                            Varman Cedar Policy Engine                             |
+-----------------------------------------------------------------------------------+
                                          |
                        Evaluates rule: step_up required
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        Webhook Dispatch & Ticket Manager                          |
+-----------------------------------------------------------------------------------+
     |                                    |                                    |
     v                                    v                                    v
+----------+                         +----------+                         +----------+
|  Slack   |                         | ServiceNow|                         | PagerDuty|
| Approval |                         | Ticket   |                         | Escalation|
+----------+                         +----------+                         +----------+
     |                                    |                                    |
     +------------------------------------+------------------------------------+
                                          |
                         Callback: Signed JWT Approval Token
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                          Execute / Resume Agent Pipeline                          |
+-----------------------------------------------------------------------------------+
```

#### Policy Extension (Cedar Code)
```cedar
// Require human step-up approval for transactions > $5,000
permit (
    principal in AgentGroup::"FinancialAgents",
    action == Action::"execute_payment",
    resource in ResourceType::"PaymentGateway"
)
when {
    context.amount > 5000
}
advice {
    "verdict": "step_up",
    "approvers": ["group:finance-leads"],
    "channel": "webhook:slack_finance_approvals",
    "timeout_seconds": 300
};
```

---

### Module C: Shadow-Mode & Policy Dry-Run Pipeline

**Goal:** Allow enterprise clients to deploy Varman without risking production downtime caused by aggressive `fail-closed` Cedar policies.

#### Implementation Strategy
Add an `enforcement_mode` directive at the root of the policy manifest:
* `observe` (Shadow Mode): Evaluates Cedar rules, logs expected verdicts, populates Merkle tree evidence, but executes actions regardless of `deny` status.
* `enforce` (Strict Mode): Enforces hard blocking on `deny` and handles `step_up` workflow blocks.

```yaml
version: 1
enforcement_mode: observe # Options: observe | enforce
default: deny

rules:
  - id: restrict-external-network
    when: { resource: external_network, operation: egress }
    verdict: deny
    log_severity: WARN
```

---

### Module D: Continuous Model Evaluation & Telemetry Exporter

**Goal:** Satisfy **NIST AI RMF (Measure 2.2)** and **ISO 42001 (A.9.2)** by monitoring accuracy decay, toxic drift, and hallucination metrics concurrently with access control.

#### Execution Architecture
1. **In-band Path:** Varman Gateway handles runtime evaluation of identity, payload boundaries, Cedar policies, and Merkle root commits.
2. **Out-of-band Path (Async):** An asynchronous worker process consumes request/response payloads from a local queue and runs lightweight evaluations (e.g., toxicity scoring, hallucination checking, schema matching).
3. **Telemetry Engine:** Export metrics via **OpenTelemetry (OTel)** to Prometheus, Datadog, or Grafana.

```
Request Payloads ──► [ In-band Execution ] ──► Return to Client / Execute Action
                           │
                           ▼ (Async Queue)
                     [ Out-of-band Evaluator ] ──► [ OpenTelemetry Exporter ]
                                                          │
                                                          ▼
                                                  Prometheus / Grafana / SIEM
```

---

## 3. Engineering Implementation Roadmap

```
                          VARMAN ROADMAP
Phase 1: Zero-Downtime          Phase 2: Operational        Phase 3: Automated
    Onboarding                       GRC                       Reporting
    [Weeks 1-4]                  [Weeks 5-8]                  [Weeks 9-12]
         │                            │                            │
         ▼                            ▼                            ▼
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│  Implement       │         │  Integrate       │         │  Build 1-Click   │
│  Shadow/Observe  │────────►│  Slack/Jira/     │────────►│  EU AI Act &     │
│  Mode            │         │  PagerDuty       │         │  NIST Compliance │
│                  │         │  Webhooks        │         │  Export Engine   │
└──────────────────┘         └──────────────────┘         └──────────────────┘
```

### Phase 1: Zero-Downtime Onboarding (Weeks 1–4)
* Implement `enforcement_mode: observe` across proxy servers.
* Update `acp-verify` to output dry-run policy audit summaries.
* Add rate-limiting and circuit-breaking options to Cedar obligations.

### Phase 2: Operational GRC & Workflow Automation (Weeks 5–8)
* Build webhook receiver for asynchronous `step_up` approval tokens.
* Expand identity assertion to include Okta/Entra group-level dynamic claims.
* Introduce automated redaction controls for prompt outputs containing custom REGEX matches.

### Phase 3: Automated Regulatory Reporting & Telemetry (Weeks 9–12)
* Add one-click export features converting Merkle ledger verification logs into **EU AI Act Article 12 Compliance Summaries** (PDF/JSON-LD).
* Build an OpenTelemetry (OTel) metrics exporter to feed compliance dashboards in Datadog, Splunk, and Grafana.