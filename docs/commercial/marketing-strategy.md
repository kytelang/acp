# Marketing and go-to-market strategy

Date: 2026-09-21
Status: the plan to reach the first 5 to 10 paying deployments with almost no upfront capital, by leading with paid pilots and letting each customer fund the validation they specifically require. Honest about where cost-transfer works and where it does not.

## 1. The strategy in one line

Land 5 to 10 lighthouse deployments in regulated enterprises through paid pilots, and let each customer fund the specific validation they demand (a penetration test of their deployment, deployment services, their own compliance mapping), so that revenue and proof arrive together and the capital in `docs/commercial/pre-launch-requirements.md` is largely deferred until customers justify it.

This is a design-partner, customer-funded motion. It suits an on-premises security product with a sharp, defensible wedge and a long enterprise sales cycle, which is exactly what ACP is.

## 2. Who we sell to

Ideal customer profile:

- Regulated or high-assurance: financial services, healthcare and pharma, government and defence, and sovereign or air-gapped environments.
- Actively deploying AI agents (coding assistants, internal copilots, agentic workflows) and feeling the control and audit gap.
- On-premises or air-gapped by mandate, so a cloud AI-security SaaS is a non-starter for them. This is where ACP has the field almost to itself.
- More than one agent vendor in play, so one policy and one evidence trail across all of them is valuable.
- A named compliance driver: EU AI Act, NIST AI RMF, ISO 42001, a regulator, or an internal audit committee asking "prove control over AI".

Buying triggers to listen for: an EU AI Act readiness programme, an internal audit finding on AI, a security team blocking an agent rollout, a data-exfiltration or shadow-AI incident, a board asking for evidence.

Where to find them: AI-governance and AI-security communities and conferences, CISO and compliance forums, EU AI Act working groups, regulated-industry user groups, and warm introductions through advisors and design partners. Open-sourcing the core (see channels) turns inbound on.

## 3. The wedge and the pitch

Lead with the sharpest thing, not the whole platform. The pitch:

"Prove your AI agents cannot exfiltrate secrets or take unauthorised actions, with cryptographically-verifiable evidence for your EU AI Act or NIST audit, fully on-premises. One complete product: the firewall, the governance, and the runtime authorization and tamper-evident evidence that neither an AI firewall nor a GRC platform gives you."

The two claims a competitor cannot match: independently-verifiable evidence, and resource-level authorization (not just content filtering), both on-premises. Everything else supports those two.

## 4. The pilot motion

Each deal moves through stages; the paid pilot is the core.

1. Outreach and qualify (weeks 0 to 2). Confirm the ICP fit and a real compliance driver. Disqualify cloud-SaaS-only buyers and single-vendor shops whose native controls already suffice.
2. Technical evaluation (weeks 2 to 4). Hand them the evaluation guide (`docs/evaluation-guide.md`), the security whitepaper (`docs/security/whitepaper.md`), and let them run the acceptance themselves: `demo/vertical/run.sh`, `acp redteam`, `acp coverage`, and `scripts/evidence-pack.sh` against a test ledger. This de-risks the "early product" objection with running proof, not slides.
3. Paid pilot (a fixed-fee proof of concept, 6 to 12 weeks). A signed statement of work: deploy in their environment (the `deploy/` reference), govern one or two real agent workflows, produce a signed evidence pack for their audit. This is where cost-transfer starts: they pay for the pilot and for any validation they require of their own deployment.
4. Production and reference (quarter 2 onward). Convert the pilot to a licence plus support, and to a named or anonymised reference and case study.

Target cadence: a pilot every 4 to 6 weeks once the motion is warm, 5 to 10 pilots in the first year, 2 to 4 converting to production.

## 5. Cost-transfer model (honest)

The point is to let customers fund validation. It works cleanly for some items and not for others.

| Validation item | Who funds it | Why |
|---|---|---|
| Penetration test of the customer's deployment | Customer, cleanly | Their security team runs it as part of procurement, or funds it in the SOW. Fix findings, re-test. Transfers per deployment. |
| Deployment and integration services | Customer, cleanly | Paid pilot or professional-services SOW. |
| Customer-specific compliance mapping (their controls, their auditor) | Customer, cleanly | You produce the evidence pack; their auditor consumes it. |
| Independent cryptographic and evidence audit | Shared, co-funded or lighthouse-funded | A single audit benefits every customer, so no one customer should carry it alone. Have the first regulated lighthouse co-fund it, or fund it once yourself as the key differentiator. Do not promise each customer a fresh audit. |
| SOC 2 | Org-level, demand-triggered, you fund | A customer cannot buy "your SOC 2" as theirs. It is your organisational asset. Start it only once paying pilots justify the spend; offer "SOC 2 Type I plus Type II in progress, plus a customer-run penetration test, plus the security whitepaper" in the interim, which regulated buyers routinely accept. |

Net: pilots and pen-tests and services are genuinely customer-funded; the crypto audit is co-funded or lighthouse-funded once; SOC 2 is triggered by demand and funded by early revenue, not by any single customer. This still defers most of the 200 thousand until customers are paying.

## 6. Pricing hypotheses

- Paid pilot: a fixed fee (for example 25 to 75 thousand depending on scope), credited against a first-year licence if they convert. This alone can fund the motion.
- Licence: annual, per governed node or per agent or per seat, tiered by scale. On-premises, so no usage metering.
- Support and SLA: a percentage of licence, with a higher tier for air-gapped and 24 by 7.
- Professional services: deployment, integration and compliance-mapping as day-rate or fixed-scope SOWs.

Validate these in the first three pilots; do not over-engineer pricing before you have signal.

## 7. Sales and evaluation assets (already built)

- Evaluation guide (`docs/evaluation-guide.md`): what it is, what it offers, is it fit for you, honestly.
- Security whitepaper and threat model (`docs/security/whitepaper.md`): the audit-ready proof.
- End-to-end acceptance (`demo/vertical/run.sh`): a running demonstration of the whole vertical plus fail-closed checks.
- Adversarial-testing and coverage commands: `acp redteam`, `acp coverage`, `acp canary-egress`.
- Compliance evidence pack (`scripts/evidence-pack.sh`): the auditor deliverable, generated from a live ledger.
- Reference deployment (`deploy/`): the artifact a pilot drops into.

Still to produce (light): a one-page wedge overview, a short demo video, and two or three vertical-specific solution briefs (finance, healthcare, government).

## 8. Objection handling

- "It is early and has no certifications." True, and the paid pilot plus a customer-run penetration test plus the running acceptance and the security whitepaper de-risk it for a proof of concept. Production hardening follows the pilot, funded by it. Point at `docs/commercial/pre-launch-requirements.md` for the honest roadmap.
- "We already have an AI firewall or a GRC platform." ACP is the complete product and does not require either, but it interoperates: it can call your firewall and feed your GRC. You are not ripping anything out.
- "Why not wait for Microsoft or Palo Alto to ship this?" Those vendors will govern their own estate, not each other's; none provides verifiable, cross-vendor, on-premises evidence. That gap is structural and is exactly ACP's ground.
- "Can we trust the crypto?" Here is the whitepaper and the isolated trust core; fund or co-fund an independent audit as part of the engagement, or wait for the shared audit.

## 9. Channels to source the first deployments

- Founder-led direct outreach into the ICP, through advisors and warm introductions. This is the primary channel for the first 5 to 10.
- Open-core: open-source the core to build adoption and trust and to turn on inbound from the AI-security and compliance communities. Monetise the enterprise features (HA, RBAC, connectors, support) and services.
- Partnerships: co-sell with a GRC platform or an identity provider that lacks runtime evidence, or with a regulated-industry systems integrator that has the relationships.
- Content: the security whitepaper, an EU AI Act evidence explainer, and the honest gap analysis as thought-leadership, not adverts.

## 10. Plan and metrics

First 90 days: finalise the wedge one-pager and demo video; open-source the core; 20 qualified ICP conversations; 1 to 2 paid pilots signed.

First 12 months: 5 to 10 paid pilots; 2 to 4 production conversions; the shared crypto audit done (co-funded); SOC 2 Type I achieved and Type II window started; 2 to 3 named or anonymised references.

Metrics that matter: qualified conversations, pilots signed, pilot-to-production conversion rate, and time-to-signed-evidence-pack (how fast a customer can produce audit evidence, which is the product's own proof).

## 11. Honest risks

- Long sales cycles in regulated buyers; the paid pilot shortens the path to revenue but not to production.
- The market is early; some buyers are not ready to spend, so qualification discipline matters.
- On-premises-only narrows the funnel to the regulated segment; that is the strategy, not a bug, but it caps the near-term TAM.
- Incumbents with distribution may bundle a good-enough version; ACP's defence is the two things they structurally will not build (verifiable cross-vendor evidence, on-premises), so keep the wedge sharp and do not drift into a feature war you cannot win on distribution.
