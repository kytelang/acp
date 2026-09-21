# Documentation index

The product is **Varman** (the Agent Control Plane); the codebase uses the `acp-` prefix and "ACP"
as the internal architecture name. This index says which documents are authoritative and current, and
which are historical records kept for context.

## Start here (buyer / evaluator)

- `evaluation-guide.md` : what Varman is, what it offers, is it fit for your purpose (honest, including where it is not).
- `../README.md` : the one-paragraph overview and pointers.
- `security/whitepaper.md` : the cryptographic and threat-model reference (audit-ready).

## Current, authoritative design

- `design/model-v2.md` : the policy model (subject = agent + human principal, object = resource, operation, obligations). The single source for the model.
- `design/platform-architecture.md` : the platform architecture across all surfaces (carries a 2026-09-21 build-status update).
- `design/enforcement.md` : unavoidability and fail-closed (guard now ships as `acp-guard`).
- `design/traffic-interception.md` : the configuration-driven interception layer (phases 1 to 5).
- `design/ml-based-content-engine.md` : the content-engine design and upgrade path (the ONNX sidecar is not yet built).
- `design/groundedness.md` : groundedness / hallucination (lexical baseline on-prem; external service for production, by decision 2026-09-21).
- `design/p2-operations.md` : operations, scale and resilience (shared state shipped as Postgres via `acp-pgstate`).
- `design/entra-setup.md` : the Entra / OIDC operator runbook.
- `positioning.md` : scope. The "Scope change" section (2026-09-20) is current; the wedge sections above it are historical.

## Status and commercial

- `pending.md` : what is built and what remains.
- `features.md` : the capability list.
- `gap-analysis.md` : the market analysis. Section 9 is current; sections 5 to 8 are the earlier "missing middle" framing, superseded.
- `commercial/pre-launch-requirements.md`, `commercial/marketing-strategy.md`, `commercial/procurement.md`, `commercial/sla-and-continuity.md`.

## Compliance and ops

- `compliance/*` : SOC 2 / control mappings / audit readiness / DPA / questionnaire. `cross-border.md` overlaps `dpa-and-subprocessors.md`.
- `ops/*` : SLOs, perf targets, deployment, cost, dependency contingency, secure SDLC.
- `model-cards/classifiers.md` : the content-firewall model cards (regex classifiers plus the trained injection model and groundedness).

## Historical records (kept for context, superseded where they disagree with the above)

- `DESIGN.md`, `PLAN.md` : the v0 design and delivery record.
- `design/phase-b-control-plane.md` ... `design/phase-f-grc.md` : build-phase records; the functionality shipped (mostly inside `acp-core`).
- `design/gap-closure.md`, `design/production-hardening.md` : implemented; retained for detail.
- `research/policy-model-study.md` : an archived pre-build research input; the model it proposed is now `design/model-v2.md`.
