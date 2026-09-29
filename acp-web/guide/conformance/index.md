# Conformance reference

Varman ships an exhaustive, versioned control catalogue and assesses an AI system against each framework's full control set. This section is the complete, code-aligned reference: one page per regulation, listing every control, how Varman supports it, how evidence is gathered, and how the report is driven.

The catalogue is the single source of truth: the assessment engine, the Statement of Applicability and the signed reports all read the same control definitions you see here, so the docs cannot drift from the product.

## The model in one paragraph

Conformance is anchored on a first-class **AI system** (the use case). You declare the **roles** you play per jurisdiction (which drive applicability), work a persisted **Statement of Applicability** per framework (applicable plus justification plus status per control), attach **evidence** whose **freshness gates the grade**, and read a **report** that grades every applicable control and rolls up a conformity summary. Evidence attached to one control automatically satisfies **crosswalked** controls in other frameworks, so you author proof once and report to many. Reports pin the catalogue version and the date, can be rendered as at a past date, and export as signed JSON-LD or CSV.

## Frameworks

| Framework | Type | Controls |
| :-- | :-- | :-- |
| [Canada AIDA](/guide/conformance/canada-aida) | statutory conformity | 7 |
| [Colorado AI Act (SB 24-205)](/guide/conformance/colorado-ai-act) | statutory conformity | 13 |
| [India DPDP Act 2023](/guide/conformance/dpdp-2023) | statutory conformity | 17 |
| [EU AI Act](/guide/conformance/eu-ai-act) | statutory conformity | 58 |
| [GDPR](/guide/conformance/gdpr) | statutory conformity | 29 |
| [ISO/IEC 23894](/guide/conformance/iso-23894) | standard | 23 |
| [ISO/IEC 27001](/guide/conformance/iso-27001) | standard | 116 |
| [ISO/IEC 42001](/guide/conformance/iso-42001) | standard | 70 |
| [NIST AI RMF](/guide/conformance/nist-ai-rmf) | standard | 72 |
| [NYC Local Law 144](/guide/conformance/nyc-ll144) | sectoral | 8 |
| [SOC 2](/guide/conformance/soc-2) | standard | 61 |
| [UK AI principles](/guide/conformance/uk-ai) | principles based | 20 |

Total: 12 frameworks, 494 controls.
