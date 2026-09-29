# UK AI principles

> Reference: UK pro-innovation AI regulation white paper (2023) &middot; catalogue version 2023 &middot; type: principles based &middot; 20 controls.

This page is the complete, code-aligned conformance reference for **UK AI principles** as Varman implements it. Every control below comes from the embedded control catalogue (`crates/acp-core/catalogue/uk-ai@2023.yaml`), the same source the assessment, the Statement of Applicability and the reports draw from, so what you read here is exactly what the product assesses against.

## How Varman supports this framework

This is a principles-based regime: there is no single binding statute, so each cross-sector principle is decomposed into regulator expectations, and the report renders as a principle-by-principle narrative backed by evidence.

Conformance is anchored on a first-class **AI system** (the use case). For a given system you:

1. Declare the **roles** you play per jurisdiction (provider, deployer, importer, distributor). Roles drive applicability, so the same system reports differently for, say, a UK deployer and an EU provider.
2. Work the **Statement of Applicability** for UK AI principles: for each control below, mark it applicable or not (with a justification for exclusions) and set its status (planned, implemented, partial, gap, not-applicable). This is persisted, not recomputed, which is what an audit expects.
3. Attach **evidence** to controls. Evidence is a first-class record with an owner and a validity window, and **freshness gates the grade**: a control claimed implemented but lacking fresh evidence is reported as partial, not conformant.
4. Read the **report**, which grades every applicable control (conformant, partial, non-conformant, not-applicable, not-assessed) and rolls the counts up. It can be rendered as at a past date, and exported as a signed JSON-LD pack or CSV.

**How data is gathered.** Most controls are evidenced by artefacts an assessor attaches (documents, test results, sign-offs). A subset is evidenced automatically from the runtime the control plane already holds: the tamper-evident decision ledger (record-keeping and logging controls), policy enforcement decisions, human oversight events (step-up approvals and the kill-switch), the content-firewall violations, and classifier-drift and red-team results. Where a control maps to a control in another framework (the **crosswalk** column), evidence authored once satisfies the mapped control automatically, so you do not re-gather the same proof for every regulation.

**How reporting is driven.** The report is a projection over the object graph: pick a system and this framework, the engine takes the applicable control set (from roles plus the persisted Statement of Applicability), grades each control from its status and the freshness of its evidence, propagates satisfaction across the crosswalk, and rolls up a conformity summary. It pins the catalogue version and the assessment date and can be signed for offline verification.

The signed export references **Accountability and governance** as this framework's record-keeping (or equivalent) anchor.

## Controls (20)

Each row is a normative obligation: its reference, what it requires (a faithful paraphrase, not the copyrighted text), who it binds, the evidence Varman uses to satisfy it, and any crosswalk to other frameworks.

| Reference | Control | What it requires | Applies to | Evidence Varman uses | Crosswalk |
| :-- | :-- | :-- | :-- | :-- | :-- |
| P1.1 | Continuous safety risk assessment | Identify, assess and keep under review the safety risks a system may pose across its lifecycle, proportionate to the context of use. | any | risk register entries with periodic review dates | eu-ai-act:Art. 9 |
| P1.2 | Technical robustness and reliability | Test that the system performs reliably and as intended under expected and foreseeable conditions, and remains resilient to errors and faults. | any | robustness and reliability test results | eu-ai-act:Art. 15 |
| P1.3 | Security against adversarial manipulation | Protect the system and its data against unauthorised access, tampering and adversarial manipulation throughout operation. | any | security controls evidence; adversarial test results | iso-27001:A.8.7 |
| P1.4 | Ongoing monitoring in operation | Monitor the system in operation so that emerging safety and security issues are detected and addressed in a timely way. | any | operational monitoring records; incident log | - |
| P2.1 | Disclosure of AI use | Make it appropriately clear to affected parties when and how an AI system is being used in a decision or interaction. | any | user-facing AI-use disclosure | eu-ai-act:Art. 50(1) |
| P2.2 | Explainability of outputs | Provide explanations of system outputs appropriate to the audience and the significance of the decision. | any | explanation artefacts; model documentation | eu-ai-act:Art. 13 |
| P2.3 | Information about capabilities and limitations | Communicate the intended purpose, capabilities and known limitations of the system to those who rely on it. | any | system documentation covering purpose, capabilities and limitations | - |
| P2.4 | Traceability of data and design decisions | Keep records of the data, models and design choices sufficient to trace how the system behaves and why. | any | traceability records; design decision log | - |
| P3.1 | Compliance with relevant law and rights | Ensure the system does not undermine the legal rights of individuals or organisations, including data protection and equality law. | any | legal and rights compliance review | gdpr:art-5 |
| P3.2 | Bias detection and mitigation | Examine the system for discriminatory outcomes across protected groups and take steps to mitigate identified bias. | any | bias examination results; mitigation records | eu-ai-act:Art. 10 |
| P3.3 | Fairness metrics appropriate to context | Define and apply fairness measures that are appropriate to the use case and justify the choice made. | any | documented fairness metrics with justification | - |
| P3.4 | Consistent and justifiable outcomes | Ensure comparable cases are treated consistently and that differences in outcome can be justified. | any | outcome consistency review; sampled decision analysis | - |
| P4.1 | Clear allocation of responsibility | Assign clear accountability for the governance and outcomes of the system to identified people or roles. | any | responsibility assignment record; governance roles | iso-42001:5.3 |
| P4.2 | Governance processes across the lifecycle | Put governance and oversight processes in place that operate through the design, deployment and operation of the system. | any | signed governance policy in force | iso-42001:8.1 |
| P4.3 | Risk management and internal controls | Maintain risk management and internal control measures proportionate to the risks the system presents. | any | risk management framework; control evidence | iso-23894:6.4 |
| P4.4 | Record-keeping and auditability | Keep records of governance decisions and system activity sufficient to support internal and external audit. | any | tamper-evident ledger of governance decisions and activity | eu-ai-act:Art. 12 |
| P5.1 | Route to contest a decision | Provide affected parties a clear and accessible route to contest or challenge a decision made or supported by the system. | any | documented contestability channel; user-facing notice | - |
| P5.2 | Human review of contested outcomes | Ensure a competent person can review a contested outcome and, where appropriate, override or correct it. | any | human review records; override log | eu-ai-act:Art. 14 |
| P5.3 | Timely and effective redress | Offer a means of redress that resolves valid complaints within a reasonable time and corrects harm where it has occurred. | any | redress workflow with resolution timestamps | - |
| P5.4 | Communication of contest and redress rights | Inform affected parties of their rights to contest a decision and seek redress, and how to exercise them. | any | user-facing notice of contest and redress rights | - |

::: tip Working this framework in the console
Compliance, then AI systems, then open a system, then Statement of Applicability, and select this framework. Tick the controls in place, attach evidence, and open Reports for the signed conformance report.
:::
