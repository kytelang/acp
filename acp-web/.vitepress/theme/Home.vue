<script setup lang="ts">
import { withBase } from 'vitepress'
import { ref, computed, onMounted } from 'vue'

// OS-detecting install block. The one-liners point at the scripts served from this site's public/
// folder, so they stay correct wherever the site is deployed.
const osTabs = [
  { id: 'macos', label: 'macOS', note: 'Apple Silicon' },
  { id: 'linux', label: 'Linux', note: 'x86_64 / arm64' },
  { id: 'windows', label: 'Windows', note: 'x86_64' },
]
const activeOs = ref('macos')
const copied = ref(false)
const shUrl = ref('https://acpdocs.web.app/install.sh')
const psUrl = ref('https://acpdocs.web.app/install.ps1')
const srvUrl = ref('https://acpdocs.web.app/install-server.sh')

const command = computed(() =>
  activeOs.value === 'windows'
    ? `powershell -c "irm ${psUrl.value} | iex"`
    : `curl -fsSL ${shUrl.value} | sh`
)
const serverCmd = computed(() => `curl -fsSL ${srvUrl.value} | sudo sh`)
const installDir = computed(() => (activeOs.value === 'windows' ? '%USERPROFILE%\\.acp' : '~/.acp'))
const binDir = computed(() => (activeOs.value === 'windows' ? '.acp\\bin' : '~/.acp/bin'))

function copyCommand() {
  if (typeof navigator !== 'undefined' && navigator.clipboard) {
    navigator.clipboard.writeText(command.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
}

onMounted(() => {
  if (typeof window === 'undefined') return
  shUrl.value = window.location.origin + withBase('/install.sh')
  psUrl.value = window.location.origin + withBase('/install.ps1')
  srvUrl.value = window.location.origin + withBase('/install-server.sh')
  const nav: any = navigator
  const pf = `${nav.userAgentData?.platform || ''} ${nav.platform || ''} ${nav.userAgent || ''}`
  if (/Win/i.test(pf)) activeOs.value = 'windows'
  else if (/Mac|iPhone|iPad|iPod/i.test(pf)) activeOs.value = 'macos'
  else if (/Linux|X11|Android/i.test(pf)) activeOs.value = 'linux'
})

// The landing mirrors the kaidb "ledger" idea, but for governance: Varman shown as the spine every
// AI action passes through, each row naming what that step buys you. Here the metaphor is literal,
// the last rows ARE a tamper-evident ledger and its verification.
const layers = [
  { n: '01', name: 'Identify', detail: 'A verified agent identity and, through OIDC or Entra, the human principal it acts for. Never spoofable, never asserted by the agent.', repl: 'who is acting, for whom', tone: 'azure' },
  { n: '02', name: 'Authorize', detail: 'One policy decides at the resource boundary: which database, secret, file, model class or network, for this subject and operation.', repl: 'the action, not just the words', tone: 'azure' },
  { n: '03', name: 'Decide', detail: 'Allow, deny, step up to a human, or allow with obligations (confirm, redact, rate-limit, budget). Default-deny with deny-overrides.', repl: 'four verdicts, fail-closed', tone: 'green' },
  { n: '04', name: 'Contain', detail: 'A scoped signed kill-switch, sequence governance that catches a toxic combination, and a data boundary a classified value cannot cross.', repl: 'stop the blast radius', tone: 'green' },
  { n: '05', name: 'Prove', detail: 'Every decision is a leaf in a Merkle log with an Ed25519 signed head, and argument payloads are encrypted at rest.', repl: 'a signed, append-only record', tone: 'orange' },
  { n: '06', name: 'Verify', detail: 'A third party re-derives the tree and checks the signature with the public key alone. No trust in our store, no private key.', repl: 'independently checkable', tone: 'orange' },
]

const pillars = [
  {
    tone: 'azure', tag: 'Runtime authorization',
    title: 'Govern the action, not just the words',
    body: 'A content filter reads text. Varman decides whether the agent may touch this database, read this secret, spend this budget or reach this host, for this human, in this sequence. One policy language, compiled to Cedar, fail-closed on any error, applied to every surface an agent acts on.',
    link: '/guide/02-policy', cta: 'Policy and authorization',
  },
  {
    tone: 'green', tag: 'Verifiable evidence',
    title: 'Prove what happened, to a third party',
    body: 'Every decision is recorded in a tamper-evident Merkle ledger with signed tree heads. An auditor verifies the whole history with the public key alone, so the proof does not depend on trusting our store. This is the capability no AI firewall and no GRC platform has.',
    link: '/guide/09-evidence', cta: 'The evidence ledger',
  },
  {
    tone: 'orange', tag: 'One complete product',
    title: 'Firewall and GRC, built in',
    body: 'A first-party content firewall (a trained injection classifier, hardened against obfuscation and indirect injection) and an evidence-backed GRC lifecycle, plus the authorization and proof neither of those tools provides. You do not assemble three products; you interoperate outward only where you already run one.',
    link: '/guide/10-content-firewall', cta: 'The content firewall',
  },
]

const chips = [
  'On-prem, vendor-neutral', 'MCP proxy', 'LLM gateway', 'Forward and TLS interception',
  'Enforcement guard', 'Coding-agent settings', 'Cedar policy', 'Verified identity (OIDC / Entra)',
  'Step-up approvals', 'Signed kill-switch', 'Merkle evidence ledger', 'Public-key verification',
  'Encryption at rest', 'HSM signing', 'Trained content firewall', 'Groundedness baseline',
  'Trajectory governance', 'Data-boundary DLP', 'Shadow-AI discovery', 'EU AI Act / NIST / ISO reports',
  'SIEM export', 'Postgres shared state',
]
</script>

<template>
  <div class="nv">
    <header class="nv-mast">
      <div class="nv-mast-line">
        <span class="nv-kicker">Varman // the Agent Control Plane (ACP)</span>
        <span class="nv-kicker nv-kicker-dim">v0.1.0</span>
      </div>
      <h1 class="nv-word">Varman</h1>
      <p class="nv-lede">
        A vendor-neutral, on-premises layer that sits in the path of what your AI agents and
        applications actually <em>do</em>, decides whether each action is allowed, and records every
        decision as tamper-evident evidence a third party can verify with a public key alone. It is
        not a chatbot filter and it is not a compliance spreadsheet. It combines what an
        <em>AI firewall</em> does, what a <em>GRC platform</em> does, and the runtime authorization and
        verifiable proof that neither provides.
      </p>
      <div class="nv-mast-links">
        <a class="nv-link nv-link-azure" :href="withBase('/guide/')">Read the guide &rarr;</a>
        <a class="nv-link" :href="withBase('/guide/01-overview')">Architecture</a>
        <a class="nv-link" :href="withBase('/guide/13-cli')">The CLI</a>
      </div>
    </header>

    <section class="nv-dl" aria-label="Download and install">
      <div class="nv-dl-aside">
        <span class="nv-eyebrow">Install</span>
        <p class="nv-dl-note">
          One command installs the client tools for your machine into an <code>.acp</code> folder in
          your home directory: the <code>acp</code> CLI, the MCP proxy, the forward proxy and the
          guard. No package manager, no system dependencies.
        </p>
        <div class="nv-badge-one">macOS &middot; Linux &middot; Windows</div>
      </div>
      <div class="nv-dl-panel">
        <div class="nv-dl-tabs" role="tablist" aria-label="Operating system">
          <button v-for="t in osTabs" :key="t.id" class="nv-dl-tab" :class="{ 'is-active': activeOs === t.id }"
            role="tab" :aria-selected="activeOs === t.id" @click="activeOs = t.id">
            <span class="nv-dl-tab-label">{{ t.label }}</span>
            <span class="nv-dl-tab-note">{{ t.note }}</span>
          </button>
        </div>
        <div class="nv-dl-cmd">
          <code class="nv-dl-code">{{ command }}</code>
          <button class="nv-dl-copy" type="button" @click="copyCommand">{{ copied ? 'Copied' : 'Copy' }}</button>
        </div>
        <p class="nv-dl-sub">
          Installs to <code>{{ installDir }}</code>, then add <code>{{ binDir }}</code> to your PATH.
          <a class="nv-link nv-link-azure" href="https://github.com/kytelang/acp/releases/latest">Manual downloads and checksums &rarr;</a>
        </p>
        <p class="nv-dl-sub">
          Running a server? Install the control plane and gateway as systemd services on a Linux host:
          <code class="nv-dl-code">{{ serverCmd }}</code>
          <a class="nv-link nv-link-azure" :href="withBase('/guide/16-setup')">The full setup runbook &rarr;</a>
        </p>
      </div>
    </section>

    <section class="nv-stack" aria-label="The governance spine">
      <div class="nv-stack-aside">
        <span class="nv-eyebrow">The spine</span>
        <p class="nv-stack-note">
          Every AI action passes through the same six steps, from establishing who is acting to
          producing a record a regulator can check without trusting us. One policy, one identity
          model, one signed ledger, one kill-switch, applied to every place AI acts.
        </p>
        <div class="nv-badge-one">one policy &middot; one ledger &middot; one kill-switch</div>
      </div>
      <ol class="nv-ledger">
        <li v-for="(l, i) in layers" :key="l.n" class="nv-row" :class="'t-' + l.tone" :style="{ '--i': i }">
          <span class="nv-row-n">{{ l.n }}</span>
          <span class="nv-row-body">
            <span class="nv-row-name">{{ l.name }}</span>
            <span class="nv-row-detail">{{ l.detail }}</span>
          </span>
          <span class="nv-row-repl">{{ l.repl }}</span>
        </li>
      </ol>
    </section>

    <section class="nv-pillars" aria-label="Three pillars">
      <article v-for="p in pillars" :key="p.tag" class="nv-pillar" :class="'t-' + p.tone">
        <span class="nv-pillar-tag">{{ p.tag }}</span>
        <h2 class="nv-pillar-title">{{ p.title }}</h2>
        <p class="nv-pillar-body">{{ p.body }}</p>
        <a class="nv-pillar-link" :href="withBase(p.link)">{{ p.cta }} &rarr;</a>
      </article>
    </section>

    <section class="nv-code" aria-label="A policy slice">
      <div class="nv-code-side">
        <span class="nv-eyebrow">One policy language</span>
        <p class="nv-code-note">
          A rule matches on the subject (agent and human principal), the object (resource and
          operation) and arguments, and carries a verdict and obligations. The same document governs
          MCP tool calls, model calls and forward-proxied HTTP. It compiles to Cedar and is signed and
          versioned; a bad deploy is rejected and the last good policy keeps serving.
        </p>
        <a class="nv-link nv-link-azure" :href="withBase('/guide/02-policy')">See the policy reference &rarr;</a>
      </div>
      <pre class="nv-pre"><code><span class="c"># one policy, every surface. default-deny once coverage is proven.</span>
<span class="k">version</span>: 1
<span class="k">default</span>: allow
<span class="k">rules</span>:
  <span class="c"># destructive database ops are never allowed</span>
  - <span class="k">id</span>: no-prod-delete
    <span class="k">when</span>: { <span class="k">resource</span>: <span class="t">database</span>, <span class="k">operation</span>: <span class="t">delete</span> }
    <span class="k">verdict</span>: <span class="f">deny</span>

  <span class="c"># a charge needs a human, with separation of duty</span>
  - <span class="k">id</span>: payments-need-approval
    <span class="k">when</span>: { <span class="k">resource</span>: <span class="t">payments</span> }
    <span class="k">verdict</span>: <span class="f">step_up</span>
    <span class="k">approvers</span>: [<span class="s">"finance"</span>]

  <span class="c"># reads are allowed, but PII is masked on the way out</span>
  - <span class="k">id</span>: mask-pii-on-reads
    <span class="k">when</span>: { <span class="k">resource</span>: <span class="t">database</span>, <span class="k">operation</span>: <span class="t">read</span> }
    <span class="k">verdict</span>: <span class="f">allow</span>
    <span class="k">obligations</span>: [{ <span class="k">kind</span>: <span class="t">redact</span>, <span class="k">fields</span>: [<span class="s">"ssn"</span>, <span class="s">"card"</span>] }]</code></pre>
    </section>

    <section class="nv-chips-wrap" aria-label="What is inside">
      <span class="nv-eyebrow">What is inside</span>
      <ul class="nv-chips">
        <li v-for="c in chips" :key="c" class="nv-chip">{{ c }}</li>
      </ul>
    </section>

    <section class="nv-read" aria-label="Start reading">
      <div class="nv-read-head">
        <h2 class="nv-read-title">Start reading</h2>
        <p class="nv-read-sub">A guide per component, from the policy language to deploying the stack.</p>
      </div>
      <div class="nv-read-cols">
        <div class="nv-read-col">
          <span class="nv-read-k">Enforcement</span>
          <a :href="withBase('/guide/03-proxy')">The MCP proxy</a>
          <a :href="withBase('/guide/04-gateway')">The LLM gateway</a>
          <a :href="withBase('/guide/05-intercept')">Forward and TLS interception</a>
          <a :href="withBase('/guide/06-guard')">The enforcement guard</a>
        </div>
        <div class="nv-read-col">
          <span class="nv-read-k">Identity and evidence</span>
          <a :href="withBase('/guide/08-identity')">Identity, registry and access</a>
          <a :href="withBase('/guide/09-evidence')">The evidence ledger</a>
          <a :href="withBase('/guide/10-content-firewall')">The content firewall</a>
          <a :href="withBase('/guide/11-containment')">Sequence, boundary, break-glass</a>
        </div>
        <div class="nv-read-col">
          <span class="nv-read-k">Run and prove it</span>
          <a :href="withBase('/guide/12-grc')">Discovery, enrolment and GRC</a>
          <a :href="withBase('/guide/13-cli')">The acp CLI</a>
          <a :href="withBase('/guide/14-operations')">Operations and deployment</a>
          <a :href="withBase('/guide/15-security')">Security and verification</a>
        </div>
      </div>
    </section>
  </div>
</template>
