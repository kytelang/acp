# ACP Console

A local web console for the Agent Control Plane, built in **Kyte** with **datastar** for live
server-sent updates. It is a strictly read-only view over acp-server's verifiable API: every figure
is served by acp-server and re-derivable from the signed evidence export, so no trust lives in the
UI (decision v1.3.1). Kyte is deliberately kept out of the enforcement/trust path; it is only the
reporting layer.

## Architecture

- `wwwroot/index.html` is the datastar shell: it loads the datastar client and opens one SSE stream
  (`data-on-load="@get('/sse/metrics')"`).
- `src/Features/Dashboard/Sse/metrics_sse.ky` streams live governance metrics: every ~2s it re-reads
  acp-server's `/report` and patches the `#metrics` fragment; the browser morphs it in place.
- `src/Features/Dashboard/Shared/acp_client.ky` is the HTTP client to acp-server (read-only).
- `src/Features/Dashboard/views/dashboard.kyx` is the KyX metrics fragment (not a full page).

## Run it locally

```sh
# 1. start acp-server (the trust core, Rust) on its default local port
acp-server --policy policy.yaml --ledger evidence.db --addr 127.0.0.1:8787

# 2. build + run the console (Kyte)
cd acp-console && kyte build && ./build/debug/bin/acp-console   # serves on http://127.0.0.1:8080
```

Open http://127.0.0.1:8080 : the metrics panel connects to acp-server and refreshes live. Fully
local, no cloud. Point `AcpClient(...)` in `main.ky` at a different acp-server base if needed.
