# Named connector adapters (Jira, Slack, MLflow)

ACP keeps neutral, generic rails (HMAC webhooks, a ticket-resolution rail, a model registry) and ships
named adapters on top of them so the common enterprise tools work out of the box. Each adapter is a thin,
pure mapping plus a small amount of server wiring; ACP embeds no vendor SDK.

## Slack (notifications)

Delivers control-plane events (GRC created/status/assigned, violations, report snapshots, approval
overdue) to a Slack incoming webhook as injection-safe Block Kit messages: every event field is a
`plain_text` value, so a hostile tool name or reason cannot forge blocks.

- Flag: `--slack-webhook-url <slack-incoming-webhook>`.
- Fires alongside the generic `--webhook-url` sink; either or both can be configured.
- Renderers: `acp_core::notify::render_slack_event` and `render_slack_message` (unit-tested for
  injection safety and Slack's 10-field section cap).

## Jira (ticketing)

Two pure mappings exchange JSON with Jira; the round-trip id is carried on an issue label.

- Outbound: `acp_core::ticket::jira::render_jira_issue(project_key, summary, description, acp_label)`
  builds a create-issue REST body, labelled `acp-approval:<id>` or `acp-grc:<id>`.
- Inbound: `POST /tickets/jira` accepts a Jira `issue_updated` webhook, verified with the same HMAC
  (`x-acp-signature` over the raw body, keyed by `--webhook-secret`) as `/tickets/callback`. Point a Jira
  Automation rule or a thin signing relay at it. `map_jira_webhook` reads the ACP label plus the new
  status and applies the resolution: a terminal "Done/Approved/Resolved" approves (a hold) or sets a GRC
  record to `approved`; "Rejected/Declined" denies or sets `rejected`; an intermediate transition, or an
  issue with no ACP label, is a no-op.
- Verified e2e: a Done transition on an `acp-grc:` issue moves the record open -> approved (re-signed);
  a non-ACP issue is a no-op; a bad signature returns 401.

## MLflow (model inventory)

Keeps the ACP model inventory in sync with the MLflow registry, running each imported model through the
normal admission scan + signed AI-BOM path so imported models are governed like manually registered ones.

- Flag: `--mlflow-url <mlflow-base-url>`. On start-up ACP GETs
  `{base}/api/2.0/mlflow/registered-models/search`, takes the highest version per registered model, and
  registers any (name, version) not already present in the default tenant. Idempotent across restarts.
- Parser: `acp_core::mlflow::models_from_search` (unit-tested). If the registry paginates, ACP logs that
  only the first page was imported (no silent truncation).
- Verified e2e: two registry models import as provider `mlflow` with their latest versions.
