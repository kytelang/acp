# Data processing and sub-processors (H0.14)

This is the data-protection baseline for ACP: the controller/processor split, the lawful basis, the
sub-processor list, and the retention and erasure position. It is drafted to be executed with legal
counsel; that review is the only open leg of H0.14. It reflects how the product actually handles
data, so the legal text and the engineering are consistent.

## Roles

The customer is the data controller. ACP (the vendor) is a data processor acting on the customer's
documented instructions, which are the configured policy and the connector settings. For the
customer's own end users whose data may appear in tool arguments, the customer remains controller
and ACP remains processor.

## What ACP processes, and what it deliberately does not

ACP is built to minimise exposure to argument content. Every evidence record stores a hash of the
arguments, not the arguments themselves. Raw arguments live in a separate, access-controlled blob
that redaction, BYOK, and erasure act on. Governance events, support bundles, and OpenTelemetry
spans carry decision metadata only, never raw arguments. The lawful basis for processing the
decision metadata is the controller's legitimate interest in governing and auditing AI-agent
actions, and, where the customer relies on it, compliance with a legal obligation to keep records.

## Sub-processors

The sub-processor list depends on the deployment. For a managed deployment it may include: the cloud
infrastructure provider, the KMS/HSM provider, the transparency-anchor service (a public log or a
timestamp authority), the notification channel providers the customer enables (Slack, Teams,
PagerDuty, email), and the identity provider (Entra ID or equivalent). A self-hosted or air-gapped
deployment removes most of these. The current list is published on the trust portal and customers
are notified before a sub-processor is added.

## Retention and erasure

Records are retained for the customer-configured period, subject to any mandated minimum for their
sector (the retention floor, enforced in code). Raw argument blobs may be redacted or erased on a
shorter schedule than the verifiable records. A right-to-erasure request removes the argument
payload without breaking the append-only log: the record and its hash remain, so the ledger still
verifies, but the underlying value is gone. Certificate-of-destruction is available where required.

## International transfers and DPIA

Where personal data crosses a border, the transfer mechanism (SCCs / IDTA plus a transfer impact
assessment) is documented per deployment. Because ACP is a monitoring product, a data protection
impact assessment is appropriate; the DPIA template in the consulting toolkit is the starting point,
and the worker-monitoring position is stated explicitly for jurisdictions that regulate it.
