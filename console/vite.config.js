import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Same-origin SPA served by acp-server from console/dist. Base '/' so the router uses clean paths;
// acp-server falls back unknown paths to index.html. In `npm run dev`, proxy the API to a running server.
const api = 'http://127.0.0.1:8787'
const proxied = ['/report','/apps','/agents','/models','/grc','/policy-store','/policy','/firewall',
  '/approvals','/auth','/groups','/agent-config','/monitor','/evidence','/endpoints','/break-glass',
  '/verify','/trust','/oversight','/vendors','/packs','/redteam','/liveness','/alerts','/tenants',
  '/principal','/events','/audit','/incident','/meta-audit']
export default defineConfig({
  plugins: [vue()],
  base: '/',
  build: { outDir: 'dist', emptyOutDir: true },
  server: { port: 5173, proxy: Object.fromEntries(proxied.map(p => [p, api])) }
})
