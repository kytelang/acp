import { defineConfig } from 'vitepress'
import kyteGrammar from './grammars/kyte.tmLanguage.json'

export default defineConfig({
  markdown: {
    // Reuse the real Kyte TextMate grammar so ```kyte and ```kyx fences (driver and console
    // examples) are highlighted. YAML, Rust, SQL and shell fences use VitePress's bundled grammars.
    languages: [
      { ...(kyteGrammar as any), name: 'kyte', scopeName: 'source.ky', aliases: ['kyx'] },
    ],
  },
  title: 'Varman (ACP)',
  base: '/',
  description:
    'Varman (the Agent Control Plane, ACP) is a vendor-neutral, on-premises layer that authorises what AI agents do at the resource boundary and records every decision as tamper-evident, independently verifiable evidence. One policy, one identity model, one signed ledger, one kill-switch, applied to every place AI acts.',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/varman-logo.svg' }],
    ['link', { rel: 'icon', type: 'image/png', href: '/favicon.png' }],
    ['meta', { name: 'theme-color', content: '#1f6feb' }],
    ['meta', { property: 'og:title', content: 'Varman (ACP), runtime authorization and verifiable evidence for AI' }],
    ['meta', {
      property: 'og:description',
      content: 'On-premises, vendor-neutral. Authorise agent actions at the resource boundary; prove what happened with a tamper-evident, public-key-verifiable ledger. A first-party content firewall and a GRC lifecycle in one product.'
    }],
  ],
  themeConfig: {
    logo: '/varman-logo.svg',
    nav: [
      { text: 'Docs', link: '/guide/' },
      { text: 'Install', link: '/guide/16-setup' },
      { text: 'Tools', link: '/guide/13-cli' },
      { text: 'Deploy', link: '/guide/14-operations' },
      { text: 'Kyte', link: 'https://kyteweb.web.app/' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Overview',
          items: [{ text: 'The guide', link: '/guide/' }],
        },
        {
          text: 'The stack',
          collapsed: false,
          items: [
            { text: '1. Overview and architecture', link: '/guide/01-overview' },
            { text: '2. Policy and authorization', link: '/guide/02-policy' },
          ],
        },
        {
          text: 'Enforcement points',
          collapsed: false,
          items: [
            { text: '3. The MCP proxy', link: '/guide/03-proxy' },
            { text: '4. The LLM gateway', link: '/guide/04-gateway' },
            { text: '5. Forward and TLS interception', link: '/guide/05-intercept' },
            { text: '6. The enforcement guard', link: '/guide/06-guard' },
            { text: '7. Governing coding agents', link: '/guide/07-native-compile' },
          ],
        },
        {
          text: 'Identity and evidence',
          collapsed: false,
          items: [
            { text: '8. Identity, registry and access', link: '/guide/08-identity' },
            { text: '9. The evidence ledger', link: '/guide/09-evidence' },
          ],
        },
        {
          text: 'Detection and containment',
          collapsed: false,
          items: [
            { text: '10. The content firewall', link: '/guide/10-content-firewall' },
            { text: '11. Sequence, boundary, break-glass', link: '/guide/11-containment' },
          ],
        },
        {
          text: 'Discovery and compliance',
          collapsed: false,
          items: [
            { text: '12. Discovery, enrolment and GRC', link: '/guide/12-grc' },
          ],
        },
        {
          text: 'Reference and operations',
          collapsed: false,
          items: [
            { text: '13. Command-line tools', link: '/guide/13-cli' },
            { text: '14. Operations and deployment', link: '/guide/14-operations' },
            { text: '15. Security and verification', link: '/guide/15-security' },
            { text: '16. Setting it all up (runbook)', link: '/guide/16-setup' },
          ],
        },
      ],
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/kytelang/acp' }],
    search: { provider: 'local' },
    outline: { level: [2, 3] },
  },
})
