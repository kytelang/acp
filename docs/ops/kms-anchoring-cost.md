# KMS and anchoring cost and rate-limit model (C4)

Signing and anchoring call external services with quotas. This projects the call volume at target
scale and states how the system degrades under throttling, so a busy period slows down safely
rather than dropping evidence.

## Call-volume model

- Signing is per signed tree head, not per record: heads are checkpointed at an interval, so KMS
  signing calls scale with the checkpoint rate, not the decision rate. At one head per few seconds,
  KMS calls per second stay well inside a standard KMS quota even at high decision volume.
- Anchoring is per head submitted to the transparency log or timestamp authority, so its rate is the
  same checkpoint rate. Rekor and RFC 3161 authorities are sized for this.
- Key-management operations (rotation) are rare and scheduled, not on the hot path.

## Degradation under throttling

- If KMS is throttled or briefly unavailable, decisions continue and records are committed to the
  durable spool and ledger; the signing of the affected head is retried, and the committed-but-
  unsigned window is bounded and alarmed (see A4). Evidence is never dropped to stay under a quota.
- If the anchor is throttled, heads queue for anchoring and are submitted when capacity returns;
  anchoring degrades by queuing, never by dropping a head.
- A self-hosted Rekor (or an internal RFC 3161 authority) is the documented fallback for air-gapped
  or high-volume deployments, removing the external rate limit entirely.

## Status

The model here sets the sizing method and the degradation behaviour. The concrete quota numbers are
confirmed against the chosen KMS and anchor at deployment.
