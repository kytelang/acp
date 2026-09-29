# Canada AIDA

> Reference: Artificial Intelligence and Data Act (Bill C-27, as introduced 2022) &middot; catalogue version 2022 &middot; type: statutory conformity &middot; 7 controls.

This page is the complete, code-aligned conformance reference for **Canada AIDA** as Varman implements it. Every control below comes from the embedded control catalogue (`crates/acp-core/catalogue/canada-aida@2022.yaml`), the same source the assessment, the Statement of Applicability and the reports draw from, so what you read here is exactly what the product assesses against.

## How Varman supports this framework

This is a statutory, binding regulation: conformance is a pass or fail against legal obligations, and the report renders as a conformity statement with the applicable articles and, where relevant, a technical-documentation structure.

Conformance is anchored on a first-class **AI system** (the use case). For a given system you:

1. Declare the **roles** you play per jurisdiction (provider, deployer, importer, distributor). Roles drive applicability, so the same system reports differently for, say, a UK deployer and an EU provider.
2. Work the **Statement of Applicability** for Canada AIDA: for each control below, mark it applicable or not (with a justification for exclusions) and set its status (planned, implemented, partial, gap, not-applicable). This is persisted, not recomputed, which is what an audit expects.
3. Attach **evidence** to controls. Evidence is a first-class record with an owner and a validity window, and **freshness gates the grade**: a control claimed implemented but lacking fresh evidence is reported as partial, not conformant.
4. Read the **report**, which grades every applicable control (conformant, partial, non-conformant, not-applicable, not-assessed) and rolls the counts up. It can be rendered as at a past date, and exported as a signed JSON-LD pack or CSV.

**How data is gathered.** Most controls are evidenced by artefacts an assessor attaches (documents, test results, sign-offs). A subset is evidenced automatically from the runtime the control plane already holds: the tamper-evident decision ledger (record-keeping and logging controls), policy enforcement decisions, human oversight events (step-up approvals and the kill-switch), the content-firewall violations, and classifier-drift and red-team results. Where a control maps to a control in another framework (the **crosswalk** column), evidence authored once satisfies the mapped control automatically, so you do not re-gather the same proof for every regulation.

**How reporting is driven.** The report is a projection over the object graph: pick a system and this framework, the engine takes the applicable control set (from roles plus the persisted Statement of Applicability), grades each control from its status and the freshness of its evidence, propagates satisfaction across the crosswalk, and rolls up a conformity summary. It pins the catalogue version and the assessment date and can be signed for offline verification.

The signed export references **Record-keeping obligations** as this framework's record-keeping (or equivalent) anchor.

## Controls (7)

Each row is a normative obligation: its reference, what it requires (a faithful paraphrase, not the copyrighted text), who it binds, the evidence Varman uses to satisfy it, and any crosswalk to other frameworks.

| Reference | Control | What it requires | Applies to | Evidence Varman uses | Crosswalk |
| :-- | :-- | :-- | :-- | :-- | :-- |
| s7 | Anonymised data governance | A person who carries out a regulated activity and processes or makes available anonymised data must establish measures governing how that data is anonymised and how it is used and managed. | provider | data anonymisation and governance measures documentation | gdpr:art-5 |
| s8 | Assessment of high-impact status | The person responsible for an artificial intelligence system must assess, in accordance with the regulations, whether it is a high-impact system. | provider | high-impact assessment record with justification | eu-ai-act:Art. 6 |
| s9 | Risk mitigation measures | The person responsible for a high-impact system must establish measures to identify, assess and mitigate the risks of harm or biased output that could result from its use, in accordance with the regulations. | provider | risk register; mitigation measures documentation | eu-ai-act:Art. 9 |
| s9(monitoring) | Monitoring of mitigation measures | The person responsible for a high-impact system must establish measures to monitor compliance with the mitigation measures and their effectiveness once the system is in operation. | provider | operational monitoring records; effectiveness review | eu-ai-act:Art. 72 |
| s10 | Record-keeping obligations | The person responsible must keep records, in accordance with the regulations, describing the measures established for anonymised data, risk assessment and mitigation, and monitoring. | provider | tamper-evident ledger of measures and monitoring records | eu-ai-act:Art. 12 |
| s11 | Plain-language public description | The person who manages or makes available a high-impact system must publish, on a publicly available website, a plain-language description of the system covering its intended use, the type of content it generates or decisions it makes, and the mitigation measures established. | provider | published plain-language description with revision history | eu-ai-act:Art. 13 |
| s12 | Notification of material harm | If the use of a high-impact system results or is likely to result in material harm, the person responsible must notify the Minister as soon as feasible, in accordance with the regulations. | provider | material-harm notification workflow with timestamps | eu-ai-act:Art. 73 |

::: tip Working this framework in the console
Compliance, then AI systems, then open a system, then Statement of Applicability, and select this framework. Tick the controls in place, attach evidence, and open Reports for the signed conformance report.
:::
