<script setup>
import { ref, onMounted } from 'vue'
import { getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const available = ref([]); const loaded = ref([]); const systems = ref([]); const target = ref('')
const msg = ref(''); const err = ref('')
async function load() {
  const a = await getOr('/packs/available', { packs: [] })
  available.value = (a.packs || []).map(sp => { const p = sp.pack || {}; return { id: p.id, framework: (p.frameworks || [])[0] || '', version: p.version, controls: (p.controls || []).length } })
  const l = await getOr('/packs', { packs: [] })
  loaded.value = l.packs || []
  systems.value = (await getOr('/systems', { systems: [] })).systems || []
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
  </div>
</template>
