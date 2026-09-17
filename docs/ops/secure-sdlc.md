# Secure development lifecycle (X.2)

How security stays current as the product changes, so the threat model does not rot and a
regression cannot slip in unreviewed.

## In continuous integration

- Build, format, and clippy with warnings-as-errors on every merge.
- The full test suite, including the trust-core assurance: Merkle inclusion/consistency invariants,
  the JCS conformance gate, the single-use-approval model check, and the fuzz corpora for the policy
  compiler and frame parser.
- The transparency self-test (`make test-transparency`) and `acp verify` on a produced pack.
- Dependency scanning (cargo-audit) and the SBOM generation.

## Review and threat model

- Every change is reviewed; a change touching the trust core (signing, ledger, policy evaluation)
  gets a heavier review and a note on which threat-model assumption it affects.
- The threat model is updated each release: new interception surfaces, new connectors, and new
  trust boundaries are added, and any assumption a change invalidates is revisited. A change to the
  self-governance surface (policy, keys, RBAC) is recorded in the meta-audit log.

## Vulnerability handling

- A vulnerability-disclosure policy and a security contact are published from GA; a bug-bounty
  scope is defined. Reports are triaged on the fastest support track, remediated, and, where a
  customer is affected, disclosed with the fix.

## Status

The CI gates and the review discipline are in place; the public disclosure policy and bug-bounty go
live at GA.
