# Customer change management and adoption kit (F13)

Turning a proxy on in front of live agents is a change to how work gets done, so adoption needs a
playbook, not just a binary. This is the kit; the console surfaces a tenant's current posture stage
and its next step so the playbook is visible in the product.

## Posture-maturity path

The same stages the enforcement engine tracks (see `acp_core::posture`):

1. Shadow: nothing is enforced, everything is recorded as would-block. Used to learn the traffic.
2. Partial: matched rules enforce; unmatched calls still pass. Enforcement begins where it is safe.
3. Default-deny: unmatched calls are denied. Enabled only once coverage clears the threshold, and
   the console shows the exact set of calls that would newly block before the operator commits.

## RACI

A RACI template names, per activity (author a policy, approve a hold, export evidence, run a
break-glass), who is Responsible, Accountable, Consulted, and Informed. It maps directly onto the
RBAC roles (PolicyAdmin, Approver, Auditor, SecurityOfficer) so the responsibility model and the
access model agree.

## Policy-author certification

A short certification path for policy authors: write a policy, test it with `acp policy-test` and
`acp canary`, and understand the shadow-to-default-deny progression before their policies reach
production. This reduces the main adoption risk, a mis-scoped policy that either blocks everything
or governs nothing.

## In-product

The console shows the tenant's posture stage and a defined next step (for example, "coverage is 62
percent; reach 80 percent to enable default-deny"), so adoption progress is legible without reading
this document.
