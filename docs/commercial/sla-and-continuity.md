# Service levels, support, and continuity (H1.6)

The commercial baseline a customer needs before relying on ACP in production. Drafted for
commercial and legal review, which is the open leg of H1.6. Numbers here are the intended
commitments, to be confirmed per contract.

## Service levels

- Control-plane availability target for the managed offering, stated as a monthly percentage with a
  defined measurement method and exclusions.
- Approval-resolution latency is a human-bound metric, so it is tracked as an operational SLO (p95
  within the policy step-up TTL), not a hard SLA, and is reported on the governance report.
- The enforcement path is designed to fail safe, not fail available: if evidence cannot be written
  durably, a gated call fails closed rather than slipping through un-recorded. This is a deliberate
  posture and is stated in the SLA so it is not read as downtime.

## Support

- Tiered support with defined response targets by severity. A security-relevant issue has the
  fastest target.
- Support can diagnose a deny or hold without ever seeing raw arguments, using correlation ids and
  the redacted diagnostic bundle (`acp diagnose`). Redaction is never disabled for support.

## Continuity and portability

- Business continuity: documented RPO/RTO with a tested restore drill; the evidence log verifies
  after restore.
- Vendor continuity: a self-host option and a source-escrow arrangement so a customer is not
  stranded if the managed service is discontinued.
- Data portability: evidence exports in an open, independently verifiable format (records plus
  signed tree heads), so a customer can take their evidence and verify it with no ACP software.
- Cyber-insurance and liability terms are set in the contract; the trust portal states the coverage
  position.

## Status

The commitments here are intended defaults. The actual SLA percentages, support response times, and
liability terms are finalised per contract with commercial and legal review.
