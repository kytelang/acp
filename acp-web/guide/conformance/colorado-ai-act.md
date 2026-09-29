# Colorado AI Act (SB 24-205)

> Reference: Colorado SB 24-205 &middot; catalogue version 2024 &middot; type: statutory conformity &middot; 13 controls.

This page is the complete, code-aligned conformance reference for **Colorado AI Act (SB 24-205)** as Varman implements it. Every control below comes from the embedded control catalogue (`crates/acp-core/catalogue/colorado-ai-act@2024.yaml`), the same source the assessment, the Statement of Applicability and the reports draw from, so what you read here is exactly what the product assesses against.

## How Varman supports this framework

This is a statutory, binding regulation: conformance is a pass or fail against legal obligations, and the report renders as a conformity statement with the applicable articles and, where relevant, a technical-documentation structure.

Conformance is anchored on a first-class **AI system** (the use case). For a given system you:

1. Declare the **roles** you play per jurisdiction (provider, deployer, importer, distributor). Roles drive applicability, so the same system reports differently for, say, a UK deployer and an EU provider.
2. Work the **Statement of Applicability** for Colorado AI Act (SB 24-205): for each control below, mark it applicable or not (with a justification for exclusions) and set its status (planned, implemented, partial, gap, not-applicable). This is persisted, not recomputed, which is what an audit expects.
3. Attach **evidence** to controls. Evidence is a first-class record with an owner and a validity window, and **freshness gates the grade**: a control claimed implemented but lacking fresh evidence is reported as partial, not conformant.
4. Read the **report**, which grades every applicable control (conformant, partial, non-conformant, not-applicable, not-assessed) and rolls the counts up. It can be rendered as at a past date, and exported as a signed JSON-LD pack or CSV.

**How data is gathered.** Most controls are evidenced by artefacts an assessor attaches (documents, test results, sign-offs). A subset is evidenced automatically from the runtime the control plane already holds: the tamper-evident decision ledger (record-keeping and logging controls), policy enforcement decisions, human oversight events (step-up approvals and the kill-switch), the content-firewall violations, and classifier-drift and red-team results. Where a control maps to a control in another framework (the **crosswalk** column), evidence authored once satisfies the mapped control automatically, so you do not re-gather the same proof for every regulation.

**How reporting is driven.** The report is a projection over the object graph: pick a system and this framework, the engine takes the applicable control set (from roles plus the persisted Statement of Applicability), grades each control from its status and the freshness of its evidence, propagates satisfaction across the crosswalk, and rolls up a conformity summary. It pins the catalogue version and the assessment date and can be signed for offline verification.

The signed export references **6-1-1703 (risk management policy and programme)** as this framework's record-keeping (or equivalent) anchor.

## Controls (13)

Each row is a normative obligation: its reference, what it requires (a faithful paraphrase, not the copyrighted text), who it binds, the evidence Varman uses to satisfy it, and any crosswalk to other frameworks.

| Reference | Control | What it requires | Applies to | Evidence Varman uses | Crosswalk |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 6-1-1701(9) | High-risk AI system definition | Identify systems that, when deployed, make or are a substantial factor in making a consequential decision, applying the statutory exclusions for narrow procedural or ancillary functions. | any | classification record identifying high-risk status with justification | eu-ai-act:Art. 6 |
| 6-1-1701(3) | Consequential decision scope | Determine whether the decision has a material legal or similarly significant effect on a consumer in areas such as education, employment, financial service, government service, health care, housing, insurance or legal service. | any | use-case registry entry mapping the decision to a consequential-decision domain | - |
| 6-1-1701(1) | Algorithmic discrimination scope | Recognise algorithmic discrimination as any unlawful differential treatment or impact that disfavours an individual or group on the basis of a protected classification under state or federal law. | any | documented understanding of algorithmic discrimination scope; protected-class mapping | - |
| 6-1-1702(1) | Reasonable care to avoid algorithmic discrimination | A developer must use reasonable care to protect consumers from any known or reasonably foreseeable risk of algorithmic discrimination arising from the intended and contracted uses of the high-risk system. | developer | reasonable-care programme documentation; risk analysis of foreseeable discrimination | eu-ai-act:Art. 9 |
| 6-1-1702(2) | Documentation and disclosures to deployers | A developer must make available to deployers the information and documentation needed to complete an impact assessment, including intended uses, known limitations, training-data summary, evaluation and bias-mitigation measures, and how the system should be used and monitored. | developer | developer-to-deployer documentation package | eu-ai-act:Art. 13 |
| 6-1-1702(4) | Public statement on high-risk systems | A developer must publish and keep current a public statement summarising the types of high-risk systems it has developed or substantially modified and how it manages known or foreseeable risks of algorithmic discrimination. | developer | published public statement with revision history | - |
| 6-1-1702(5) | Disclosure of known discrimination to the Attorney General | A developer must disclose to the Attorney General and to known deployers any known or reasonably foreseeable risk of algorithmic discrimination, within the statutory timeframe after discovery. | developer | disclosure workflow with timestamps; notification records | eu-ai-act:Art. 73 |
| 6-1-1703(2) | Risk management policy and programme | A deployer must implement and maintain a risk management policy and programme for the high-risk system that is reasonable in light of guidance and a recognised risk-management framework such as the NIST AI Risk Management Framework or ISO/IEC 42001. | deployer | signed risk management policy in force; programme documentation aligned to a recognised framework | nist-ai-rmf:GOVERN-1.1 |
| 6-1-1703(3) | Impact assessment of the high-risk system | A deployer must complete an impact assessment before deployment and at least annually, covering purpose, benefits, known risks of algorithmic discrimination and mitigation, data categories, performance metrics and post-deployment monitoring. | deployer | completed impact assessment; annual review record | eu-ai-act:Art. 27 |
| 6-1-1703(4) | Consumer notice before a consequential decision | A deployer must notify a consumer when a high-risk system is used to make, or is a substantial factor in making, a consequential decision about that consumer, and describe the system and its purpose. | deployer | consumer-facing notice; delivery records | eu-ai-act:Art. 50(1) |
| 6-1-1703(4)(b) | Right to correct data and to appeal | When a consequential decision is adverse to a consumer, a deployer must give the consumer an opportunity to correct inaccurate personal data and, where technically feasible, to appeal for human review. | deployer | correction and appeal workflow; human-review records | eu-ai-act:Art. 14 |
| 6-1-1703(5) | Public statement on deployed high-risk systems | A deployer must publish and keep current a public statement summarising the types of high-risk systems it deploys and how it manages known or foreseeable risks of algorithmic discrimination. | deployer | published public statement with revision history | - |
| 6-1-1703(7) | Disclosure of discrimination to the Attorney General | A deployer that discovers the high-risk system has caused algorithmic discrimination must notify the Attorney General within the statutory timeframe after discovery. | deployer | disclosure workflow with timestamps; notification records | eu-ai-act:Art. 73 |

::: tip Working this framework in the console
Compliance, then AI systems, then open a system, then Statement of Applicability, and select this framework. Tick the controls in place, attach evidence, and open Reports for the signed conformance report.
:::
