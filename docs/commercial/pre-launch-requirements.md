# Pre-launch requirements

Date: 2026-09-21
Status: the honest gap between what ACP is today (a working, tested reference implementation) and what it needs to be to sell to a regulated enterprise. This document separates what code can close from what needs money, time and external parties, and sizes the spend. It is deliberately not a pitch: the point is to plan, not to persuade.

## 1. Where we stand

ACP is a complete, tested platform for the wedge it targets: a vendor-neutral, verifiable runtime authorization and evidence layer for AI actions, with a first-party content firewall and a Credo-class GRC lifecycle layered on top. As of this writing the workspace has 369 tests passing and a 10 out of 10 end-to-end acceptance run for the core vertical.

What is built and verified:

- The bulletproof spine: Agent (verified, un-spoofable identity) to Action to Policy to Decision (allow / deny / step-up / obligations, fail-closed) to Human approval (inbox with separation of duty) to Execution to Cryptographic evidence (Merkle ledger with signed tree heads and an append-only store) to Independent verification (ledger and standalone pack, public key only). Tampering fails verification; an invalid token is rejected.
- Content firewall on both surfaces (gateway prompts and proxy tool calls): signatures plus a trained ML detector, hardened against obfuscation (base64, zero-width, homoglyph, despacing) and indirect injection (poisoned tool results), with a continuous adversarial-testing gate.
- GRC lifecycle: control library, EU AI Act risk assessment, conformity workflow, attestations, use-case lifecycle, model cards, framework reports, SIEM export.
- Runtime governance beyond single calls: intent / trajectory governance (toxic combinations, velocity) and destination-aware data-boundary enforcement.
- Platform mechanics: HTTP/API interception (registry, forward proxy, TLS interception), supply-chain admission and a signed AI-BOM, coverage attestation and an egress canary, a scoped signed kill-switch, and shared state (budgets and tool pins) verified across replicas on Postgres.

This is a strong reference implementation. It is not yet a commercial product. The rest of this document is why, and what it takes.

## 2. The four gaps

### 2.1 Deployment and resilience

Today: single-node verified, mock Entra identity, HA and DR designed but not run in anger, no production deployments.

To close:

- Real Entra cutover. The code path is built and tested against a mock. Flipping it needs a tenant access token from the operator; then wire and test. Small (about a day) once the token exists.
- HA and DR in a real environment. Multi-node deployment behind a load balancer with the Postgres-backed shared state (already in code), ledger replication (Litestream or LiteFS, or Postgres for the ledger), an active plus warm-standby control plane, and rehearsed failover and disaster-recovery drills. This is infrastructure and operations work: an SRE, a real cluster, a few weeks, and cloud or on-prem cost.
- Production deployment. Needs a real environment with real traffic, which means a design partner. Cannot be manufactured; the reference deployment (below) is what a partner drops into.

Engineering that removes external friction (sweat equity): a reference deployment (Helm chart, docker-compose, systemd units), replication configuration, and a scripted failover drill.

### 2.2 Security proof points

This is the bucket a security buyer scrutinises first, and it is almost entirely money, external firms and a running system. No amount of in-house code substitutes for a third party signing off.

- Independent cryptographic and evidence audit. A review of the Merkle ledger, signing and attestation by a named firm (for example Trail of Bits, NCC Group, Cure53). This is the single highest-value proof, because verifiable evidence is the most ownable claim ACP has. Roughly 50 to 75 thousand, a few weeks to a couple of months, against a code base made audit-ready.
- Third-party penetration test. A security firm testing the deployed system. Roughly 20 to 35 thousand, a few weeks, needs a live deployment. Then fix and re-test the findings.
- SOC 2. Tooling (Vanta or Drata) plus a CPA auditor, with policies, controls and evidence collected over a window. Type I is achievable in about two to three months; Type II requires a six to twelve month observation window by definition, which money cannot compress. Roughly 30 to 50 thousand for the first cycle plus internal effort.

Engineering that removes external friction (sweat equity): an audit-ready security whitepaper and threat model (auditors charge for ramp-up, so a clean specification cuts cost and time), and dogfooding ACP's own GRC module to auto-generate the SOC 2 control-evidence pack.

### 2.3 Packaging and go-to-market surface

Today: no installers, developer docs rather than buyer docs, no pricing, no support or SLAs, a basic console.

To close, and where code helps most:

- Installers and packaging. Signed release binaries (cosign), reproducible builds, an SBOM, container images, a Helm chart, systemd units, a one-line installer. Mostly buildable in-house.
- Buyer documentation. A security whitepaper, a trust and architecture document, a deployment guide, a compliance mapping pack, a data-processing addendum and data-flow diagrams. Much of the compliance material already exists under docs/compliance. Draftable in-house.
- Console at scale. Hardening the current basic console into a production admin UI is real front-end work, weeks to months.
- Pricing, support and SLAs. Pricing is a business decision informed by market research (hypotheses can be drafted). Support and SLAs are an organisational function (people, on-call, ticketing), not code, and require hiring and process.

### 2.4 Customers and references

Today: none. This is pure go-to-market: outreach, pilots, and converting pilots into named references. It needs a founder or sales motion, a network, and time. It cannot be built in code. What can be built is the enablement: a turnkey demo and pilot environment, a security one-pager, the wedge pitch, and an ROI and audit-evidence story that makes a pilot easy to approve.

## 3. What it costs

Approximately 200 thousand in cash is a reasonable estimate for the external validation, certifications, infrastructure and some contract engineering to make ACP credible and installable, if the team's own labour is treated as equity and not counted.

| Line item | Realistic range |
|---|---|
| Independent crypto and evidence audit | 50 to 75 thousand |
| Third-party penetration test | 20 to 35 thousand |
| SOC 2 (Type I then first Type II cycle) | 30 to 50 thousand |
| Infrastructure (HA, staging, demo) | 15 to 30 thousand per year |
| Contract engineering (packaging, HA, console), reducible by sweat equity | 20 to 40 thousand |
| Total | about 135 to 230 thousand |

### Three caveats that break "200 thousand equals done"

1. It excludes salaries. The 200 thousand is the external and validation spend. If it must also pay the engineers and founder doing six to eighteen months of work, it is thin: one senior engineer for a year is already roughly 150 to 200 thousand fully loaded. The number works only if the labour is the team's own equity.
2. Money cannot compress SOC 2 Type II. Type I in two to three months, but Type II needs a six to twelve month observation window regardless of budget. "All certificates" fully is a nine to twelve month calendar item. Buyers will accept Type I plus "Type II in progress" in the interim.
3. It makes ACP credible, not sold. Certificates, an audit and a deployable build get a security buyer to take ACP seriously and pilot it. Acquiring customers is a separate go-to-market spend and motion. Do not conflate auditable and installable with generating revenue.

There is also a recurring tail: SOC 2 is annual (roughly 30 to 50 thousand per year), penetration tests are periodic, and infrastructure is ongoing. The 200 thousand is mostly the one-time push.

## 4. Timeline

- To a sellable version one for a first regulated design partner: roughly three to six months, one or two strong engineers plus an SRE, about 100 to 250 thousand for the penetration test, crypto audit, SOC 2 Type I and infrastructure, plus a founder doing go-to-market.
- To a credible enterprise product with SOC 2 Type II and a couple of references: nine to eighteen months and more spend.

The majority of the remaining distance is not engineering. The product is already feature-complete relative to the wedge. The gaps are external validation, a running HA deployment, and customers; only the deployment, packaging and audit-readiness parts are things in-house code can materially move.

## 5. Marketability and monetization (context)

The wedge is real and defensible: tamper-evident, independently-verifiable evidence (which no incumbent has), resource-level authorization (only Noma is close), and vendor-neutral on-premises and air-gapped operation. The buyer is a regulated enterprise deploying AI agents that must prove control for the EU AI Act or NIST: finance, healthcare, pharma, government, defence, sovereign.

The headwinds are equally real: a crowded, consolidating market (Lakera into Check Point, Robust Intelligence into Cisco, Protect AI into Palo Alto, Prompt Security into SentinelOne, CalypsoAI into F5), an early and confused buyer (security versus GRC versus platform), an on-premises-only posture that cuts off the cloud-native segment, and a trust deficit until certificates and references exist.

Monetization models that fit, given the on-premises and vendor-neutral positioning:

- Open-core: open the core to build adoption and trust, monetise enterprise features (HA, RBAC, connectors, support). Slow but credible for security infrastructure.
- Enterprise licence plus support, per node or per agent or seat, into the regulated niche.
- The verifiable evidence layer sold into GRC and compliance budget, partnering with Credo or OneTrust as their missing runtime-evidence source rather than competing.
- OEM, partnership or acqui-hire: the tamper-evident evidence and cross-vendor authorization IP is attractive to an identity provider, a GRC platform or a security vendor lacking it.

The sharpest wedge to lead with, rather than the whole platform: prove that AI agents cannot exfiltrate secrets or take unauthorised actions, with cryptographically-verifiable evidence for an EU AI Act or NIST audit, fully on-premises. This leans on the two genuine monopolies (verifiable evidence and resource-level authorization on-premises), sells to a real budget (compliance), and sidesteps the content-firewall shootout that cannot be won on distribution.

## 6. Sweat-equity acceleration plan (what in-house code can do now)

These reduce the cash outlay and unlock the auditor and the first buyer:

1. Reference HA deployment: Helm chart, docker-compose and systemd units, Postgres-backed shared state, ledger replication, and a scripted failover drill, so "run in anger" becomes real.
2. Signed, reproducible release packaging: cosign signatures, an SBOM, and a one-line installer, so it is installable.
3. Security whitepaper and threat model: makes the cryptographic and evidence claim audit-ready and cuts the external audit cost and time.
4. Dogfood ACP's GRC to auto-generate the SOC 2 control-evidence pack.
5. Design-partner demo kit: a turnkey environment, the wedge pitch, and an audit-evidence one-pager.

Recommended order: start with item one (HA reference deployment) and item three (audit-ready security whitepaper), because they unlock the two things a real buyer and a real auditor ask for first, and they are where in-house work removes the most external friction.

## 7. Pre-launch checklist

- [ ] Real Entra cutover completed and tested (needs a tenant token).
- [ ] Reference HA deployment (Helm / compose / systemd) with a rehearsed failover and DR drill.
- [ ] Signed, reproducible release with an SBOM and a one-line installer.
- [ ] Security whitepaper and threat model published (audit-ready).
- [ ] Independent cryptographic and evidence audit engaged and passed.
- [ ] Third-party penetration test engaged, findings fixed and re-tested.
- [ ] SOC 2 Type I achieved; Type II observation window started.
- [ ] Buyer documentation set (trust, deployment, compliance mapping, DPA).
- [ ] Pricing and packaging decided; support and SLA model defined.
- [ ] One or two design partners in a paid or reference pilot.
