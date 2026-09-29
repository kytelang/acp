# NYC Local Law 144

> Reference: NYC Local Law 144 of 2021; DCWP final rules &middot; catalogue version 2023 &middot; type: sectoral &middot; 8 controls.

This page is the complete, code-aligned conformance reference for **NYC Local Law 144** as Varman implements it. Every control below comes from the embedded control catalogue (`crates/acp-core/catalogue/nyc-ll144@2023.yaml`), the same source the assessment, the Statement of Applicability and the reports draw from, so what you read here is exactly what the product assesses against.

## How Varman supports this framework

This is a sectoral law with a narrow scope: conformance is a short, specific control set (for example a bias audit and its notices), assessed and evidenced like any other framework.

Conformance is anchored on a first-class **AI system** (the use case). For a given system you:

1. Declare the **roles** you play per jurisdiction (provider, deployer, importer, distributor). Roles drive applicability, so the same system reports differently for, say, a UK deployer and an EU provider.
2. Work the **Statement of Applicability** for NYC Local Law 144: for each control below, mark it applicable or not (with a justification for exclusions) and set its status (planned, implemented, partial, gap, not-applicable). This is persisted, not recomputed, which is what an audit expects.
3. Attach **evidence** to controls. Evidence is a first-class record with an owner and a validity window, and **freshness gates the grade**: a control claimed implemented but lacking fresh evidence is reported as partial, not conformant.
4. Read the **report**, which grades every applicable control (conformant, partial, non-conformant, not-applicable, not-assessed) and rolls the counts up. It can be rendered as at a past date, and exported as a signed JSON-LD pack or CSV.

**How data is gathered.** Most controls are evidenced by artefacts an assessor attaches (documents, test results, sign-offs). A subset is evidenced automatically from the runtime the control plane already holds: the tamper-evident decision ledger (record-keeping and logging controls), policy enforcement decisions, human oversight events (step-up approvals and the kill-switch), the content-firewall violations, and classifier-drift and red-team results. Where a control maps to a control in another framework (the **crosswalk** column), evidence authored once satisfies the mapped control automatically, so you do not re-gather the same proof for every regulation.

**How reporting is driven.** The report is a projection over the object graph: pick a system and this framework, the engine takes the applicable control set (from roles plus the persisted Statement of Applicability), grades each control from its status and the freshness of its evidence, propagates satisfaction across the crosswalk, and rolls up a conformity summary. It pins the catalogue version and the assessment date and can be signed for offline verification.

The signed export references **Bias audit publication** as this framework's record-keeping (or equivalent) anchor.

## Controls (8)

Each row is a normative obligation: its reference, what it requires (a faithful paraphrase, not the copyrighted text), who it binds, the evidence Varman uses to satisfy it, and any crosswalk to other frameworks.

| Reference | Control | What it requires | Applies to | Evidence Varman uses | Crosswalk |
| :-- | :-- | :-- | :-- | :-- | :-- |
| bias-audit | Annual independent bias audit | Before using an automated employment decision tool, and within one year of the audit, the tool must undergo an impartial bias audit conducted by an independent auditor that computes selection or scoring rates and impact ratios across sex, race and ethnicity categories, and their intersections. | deployer | independent bias audit report with selection rates and impact ratios | eu-ai-act:Art. 10 |
| bias-audit-independence | Auditor independence | The bias audit must be performed by an independent auditor that was not involved in using, developing or distributing the tool and has no financial interest that would compromise impartiality. | deployer | auditor independence attestation; engagement scope | - |
| publication-summary | Publication of bias audit summary results | A summary of the most recent bias audit results, including the source and explanation of the data, the selection or scoring rates and the impact ratios, together with the distribution date of the tool, must be published on the employer or agency website. | deployer | published audit summary with distribution date | - |
| publication-retention | Availability of published results | The published summary of results must remain publicly available until at least six months after the tool is no longer used for an employment decision. | deployer | publication record with availability window | - |
| notice-candidate | Ten business-day candidate notice | Candidates and employees who reside in New York City must be notified at least ten business days before an automated employment decision tool is used, that such a tool will be used to assess them. | deployer | candidate notice template; delivery records with timestamps | eu-ai-act:Art. 50(1) |
| notice-qualifications | Notice of job qualifications and characteristics | The notice must state the job qualifications and characteristics that the automated employment decision tool will use in the assessment. | deployer | notice content listing job qualifications and characteristics | - |
| notice-datatype | Notice of data collected and data source | On request, the employer or agency must disclose the type of data collected for the tool, the source of that data and its data retention policy, within the statutory timeframe. | deployer | data-type and source disclosure record | - |
| notice-alternative | Alternative process and accommodation notice | The notice must explain how a candidate or employee may request an alternative selection process or a reasonable accommodation under other laws, where such a process is available. | deployer | notice content describing alternative process and accommodation route | eu-ai-act:Art. 14 |

::: tip Working this framework in the console
Compliance, then AI systems, then open a system, then Statement of Applicability, and select this framework. Tick the controls in place, attach evidence, and open Reports for the signed conformance report.
:::
