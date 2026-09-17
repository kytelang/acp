# Accessibility and inclusive design (v3.5)

The approval inbox and console are used under time pressure during an incident, so accessibility is
an operational requirement, not only a compliance one. This states the target and the approach; the
formal conformance sign-off (the VPAT) is completed by an accessibility reviewer, which is the open
leg.

## Target

WCAG 2.1 AA, aligned with EN 301 549 and Section 508, for the approval inbox and the reporting
console.

## Approach baked into the UI

- The approval inbox is server-rendered semantic HTML (maud), so it is keyboard-navigable and works
  with assistive technology without a heavy client framework.
- Decisions are conveyed by text and structure, not colour alone: a deny, a hold, and an approval
  are labelled, not merely coloured.
- Every actionable control (approve, deny) is a real button with an accessible name that includes
  the tool and the impact, so a screen-reader user hears what they are approving.
- Content escaping (already required for the injection-safe rendering) keeps hostile input from
  breaking the page structure that assistive technology depends on.

## Sign-off

A VPAT (Voluntary Product Accessibility Template) is produced by an accessibility reviewer against
the target above and published on the trust portal. That review is the [e] leg of this item.
