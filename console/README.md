# Varman console (Vue 3)

The web console for the Varman control plane, embedded in `acp-server`.

- Stack: Vue 3, Vue Router, Pinia, TailwindCSS, Lucide icons, Vite. Plain JavaScript (no TypeScript).
- Build: `npm install && npm run build` produces `dist/`.
- Single binary (optional): build `acp-server` with `--features embed-console` (after `npm run build`) to bake `dist/` into the binary, so no `dist/` needs to sit beside the binary at runtime.
- Serving: `acp-server` serves `dist/` at `/` (SPA fallback for client routes) and keeps the JSON API
  on the same origin and port. It auto-discovers `console/dist` from the working directory, or use
  `--console <dir>` / `ACP_CONSOLE_DIR`.
- Dev: `npm run dev` runs Vite on :5173 and proxies the API to a local `acp-server` on :8787.

The console calls the control-plane endpoints directly with the `x-acp-tenant` header and a per-role
dev-token for writes (a forwarded bearer wins when present).
