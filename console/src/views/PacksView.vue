<script setup>
import { ref, onMounted } from 'vue'
import { getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'
import { computed } from 'vue'

const available = ref([]); const loaded = ref([]); const systems = ref([]); const target = ref('')
const msg = ref(''); const err = ref('')
const showBuilder = ref(false); const packName = ref(''); const builderFw = ref('eu-ai-act')
const templates = ref([]); const checked = ref({}); const berr = ref('')
const frameworkItems = computed(() => { const t = templates.value.find(x => x.framework === builderFw.value); return t ? (t.items || []) : [] })
const selectedCount = computed(() => Object.values(checked.value).filter(Boolean).length)
function openBuilder() { packName.value = ''; checked.value = {}; berr.value = ''; showBuilder.value = true }
async function createPack() {
  berr.value = ''
  if (!packName.value.trim()) { berr.value = 'Name is required.'; return }
  const controls = Object.entries(checked.value).filter(([, v]) => v).map(([k]) => { const i = k.indexOf(':'); return { framework: k.slice(0, i), control_id: k.slice(i + 1) } })
  if (!controls.length) { berr.value = 'Select at least one control.'; return }
  try { const r = await post('/packs/custom', { name: packName.value.trim(), controls }, 'PolicyAdmin'); showBuilder.value = false; msg.value = `Custom pack "${r.id}" created with ${r.controls} controls.`; await load() }
  catch (e) { berr.value = String(e.message || e) }
}
async function load() {
  const a = await getOr('/packs/available', { packs: [] })
  available.value = (a.packs || []).map(sp => { const p = sp.pack || {}; return { id: p.id, framework: (p.frameworks || [])[0] || '', version: p.version, controls: (p.controls || []).length } })
  const l = await getOr('/packs', { packs: [] })
  loaded.value = l.packs || []
  systems.value = (await getOr('/systems', { systems: [] })).systems || []
  templates.value = ((await getOr('/grc/templates', { templates: [] })).templates || []).filter(x => x.kind === 'checklist')
  if (!target.value && systems.value.length) target.value = systems.value[0].id
}
async function apply(pack, byFramework) {
  msg.value = ''; err.value = ''
  if (!target.value) { err.value = 'Pick a target system first.'; return }
  const body = byFramework ? { framework: pack.framework } : { pack_id: pack.id }
  try { const r = await post(`/systems/${target.value}/apply-pack`, body, 'GrcAuthor'); msg.value = `Applied "${pack.id}" to the system: seeded ${r.seeded}, skipped ${r.skipped} (already present).` }
  catch (e) { err.value = String(e.message || e) }
}
onMounted(load)
</script>
<template>
  <div class="grid gap-4">
    <Card title="Policy packs" subtitle="reusable control bundles you apply to an AI system to seed its requirements">
      <template #cta><Btn size="sm" @click="openBuilder">New custom pack</Btn></template>
      <p class="text-xs text-dim mb-3">
        A policy pack is a signed, versioned bundle of controls. Applying a pack to an AI system seeds that
        system's Statement of Applicability (the controls it must meet), so you do not start a framework from
        scratch. Applying is non-destructive: controls you have already worked are left untouched.
      </p>
      <label class="text-xs text-dim">Apply to system
        <select v-model="target" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm min-w-72">
          <option v-for="s in systems" :key="s.id" :value="s.id">{{ s.name }} ({{ s.id }})</option>
          <option v-if="!systems.length" value="">no systems yet - register one under AI systems</option>
        </select>
      </label>
      <p v-if="msg" class="text-ok text-sm mt-3">{{ msg }}</p>
      <p v-if="err" class="text-bad text-sm mt-3">{{ err }}</p>
    </Card>

    <Card title="Built-in framework packs" subtitle="one per framework, derived from the catalogue and signed">
      <DataTable :columns="['Pack','Framework','Version','Controls','']">
        <tr v-for="p in available" :key="p.id" class="border-b border-line/60">
          <td class="py-2 pr-4 font-mono text-xs">{{ p.id }}</td>
          <td class="py-2 pr-4">{{ p.framework }}</td>
          <td class="py-2 pr-4 text-dim">{{ p.version }}</td>
          <td class="py-2 pr-4">{{ p.controls }}</td>
          <td class="py-2 pr-4 text-right"><Btn size="sm" :disabled="!target" @click="apply(p, true)">Apply to system</Btn></td>
        </tr>
      </DataTable>
    </Card>

    <Card title="Loaded packs" subtitle="signed packs loaded into the control plane (custom or distributed)">
      <DataTable :columns="['Pack','Version','Frameworks','Controls','Signed','']">
        <tr v-for="p in loaded" :key="p.id" class="border-b border-line/60">
          <td class="py-2 pr-4 font-mono text-xs">{{ p.id }}</td>
          <td class="py-2 pr-4 text-dim">{{ p.version }}</td>
          <td class="py-2 pr-4">{{ (p.frameworks || []).join(', ') }}</td>
          <td class="py-2 pr-4">{{ p.controls }}</td>
          <td class="py-2 pr-4"><Badge :kind="p.verified ? 'ok' : 'bad'">{{ p.verified ? 'verified' : 'unverified' }}</Badge></td>
          <td class="py-2 pr-4 text-right"><Btn size="sm" variant="ghost" :disabled="!target" @click="apply(p, false)">Apply to system</Btn></td>
        </tr>
        <tr v-if="!loaded.length"><td colspan="6" class="py-4 text-center text-dim">No custom packs loaded.</td></tr>
      </DataTable>
    </Card>

    <Modal v-if="showBuilder" title="New custom policy pack" wide @close="showBuilder = false">
      <div class="grid gap-3">
        <label class="text-xs text-dim">Pack name<input v-model="packName" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. EU high-risk starter" /></label>
        <div class="flex items-center gap-3">
          <label class="text-xs text-dim">Browse framework
            <select v-model="builderFw" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm min-w-56">
              <option v-for="t in templates" :key="t.framework" :value="t.framework">{{ t.name }}</option>
            </select>
          </label>
          <div class="ml-auto text-sm"><Badge kind="ver">{{ selectedCount }} selected</Badge></div>
        </div>
        <div class="border border-line rounded-lg p-3 max-h-80 overflow-y-auto">
          <div class="text-xs text-dim mb-2">Tick controls to add. Switch framework to add controls from other regulations, the selection is kept.</div>
          <label v-for="c in frameworkItems" :key="c.control_id" class="flex items-start gap-2 text-[13px] py-0.5">
            <input type="checkbox" v-model="checked[`${builderFw}:${c.control_id}`]" class="mt-1" />
            <span><span class="font-mono text-xs text-dim mr-1">{{ c.reference || c.control_id }}</span>{{ c.title }}</span>
          </label>
        </div>
        <div class="flex items-center gap-3"><Btn @click="createPack">Create pack</Btn><span v-if="berr" class="text-bad text-sm">{{ berr }}</span></div>
      </div>
    </Modal>
  </div>
</template>
