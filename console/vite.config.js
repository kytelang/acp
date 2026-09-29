import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Same-origin SPA served by acp-server from console/dist. Base '/' so the router uses clean paths;
// acp-server serves the flat asset files and falls back unknown paths to index.html.
//
// Output is deliberately FLAT and STABLE so acp-server can expose fixed files without hashed names:
//   dist/index.html  -> the entry page (Vite rewrites the script/style links to /main.js and /main.css)
//   dist/main.js     -> the whole app in one bundle (dynamic route imports inlined)
//   dist/main.css    -> all styles in one file
// This mirrors the plancks ui project and avoids per-build hashed filenames under assets/.
const api = 'http://127.0.0.1:8787'
const proxied = ['/report','/apps','/agents','/models','/grc','/policy-store','/policy','/firewall',
  '/approvals','/auth','/groups','/agent-config','/monitor','/evidence','/endpoints','/break-glass',
  '/verify','/trust','/oversight','/vendors','/packs','/redteam','/liveness','/alerts','/tenants',
  '/principal','/events','/audit','/incident','/meta-audit']

export default defineConfig({
  plugins: [vue()],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,            // one stylesheet -> main.css
    assetsInlineLimit: 100000000,   // inline any small assets (icons/fonts) into the bundle
    rollupOptions: {
      output: {
        inlineDynamicImports: true, // fold the lazy route chunks into the single entry bundle
        entryFileNames: 'main.js',
        assetFileNames: (info) => {
          const name = info.name || ''
          if (name.endsWith('.css')) return 'main.css'
          return '[name][extname]'
        }
      }
    }
  },
  server: { port: 5173, proxy: Object.fromEntries(proxied.map(p => [p, api])) }
})
