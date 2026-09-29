<script setup>
import { ref, onMounted, computed } from 'vue'
import { get, getOr, download } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const frameworks = ref([])
const selected = ref('eu-ai-act')
const role = ref('')          // '', provider, deployer
const tier = ref('high')
const jurisdiction = ref('')
const report = ref(null)
const err = ref('')

onMounted(async () => {
  const t = await getOr('/grc/templates', { templates: [] })
  frameworks.value = (t.templates || []).filter(x => x.kind === 'checklist')
    .map(x => ({ slug: x.framework, name: x.name, type: x.framework_type, version: x.version }))
  if (frameworks.value.length && !frameworks.value.find(f => f.slug === selected.value)) selected.value = frameworks.value[0].slug
  await load()
})

function query() {
  const p = new URLSearchParams()
  if (role.value) p.set('role', role.value)
  if (tier.value) p.set('tier', tier.value)
  if (jurisdiction.value) p.set('jurisdiction', jurisdiction.value)
  const q = p.toString()
  return q ? `?${q}` : ''
}
async function load() {
  err.value = ''
  try { report.value = await get(`/report/framework/${selected.value}${query()}`) }
  catch (e) { err.value = String(e.message || e); report.value = null }
}
const sum = computed(() => report.value?.conformity_summary || {})
function cmark(c) {
  return { conformant: 'ok', partial: 'warn', 'non-conformant': 'bad', 'not-applicable': 'muted', 'not-assessed': 'ver' }[c] || 'muted'
}
function dl(kind) {
  const q = query()
  if (kind === 'csv') download(`/report/framework/${selected.value}/csv${q}`, 'Auditor', `${selected.value}-report.csv`)
  else download(`/report/framework/${selected.value}/pack`, 'Auditor', `${selected.value}-compliance-pack.jsonld`)
}
</script>
<template>
  <div class="grid gap-4">
    <Card title="Compliance report" subtitle="exhaustive per-control conformance">
      <div class="flex flex-wrap items-end gap-3">
        <label class="text-xs text-dim">Framework
          <select v-model="selected" @change="load" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm min-w-56">
            <option v-for="f in frameworks" :key="f.slug" :value="f.slug">{{ f.name }}</option>
          </select>
        </label>
        <label class="text-xs text-dim">Role
          <select v-model="role" @change="load" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option value="">provider + deployer</option>
            <option value="provider">provider</option>
            <option value="deployer">deployer</option>
            <option value="developer">developer</option>
          </select>
        </label>
        <label class="text-xs text-dim">Risk tier
          <select v-model="tier" @change="load" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option value="high">high</option><option value="limited">limited</option>
            <option value="minimal">minimal</option><option value="unacceptable">unacceptable</option>
          </select>
        </label>
        <label class="text-xs text-dim">Jurisdiction
          <input v-model="jurisdiction" @keyup.enter="load" placeholder="e.g. UK" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm w-28" />
        </label>
        <Btn size="sm" variant="ghost" @click="load">Apply</Btn>
        <div class="ml-auto flex gap-2">
          <Btn size="sm" variant="ghost" @click="dl('csv')">CSV</Btn>
          <Btn size="sm" @click="dl('pack')">Signed pack</Btn>
        </div>
      </div>
      <p v-if="err" class="text-bad text-sm mt-3">{{ err }}</p>
    </Card>

    <div v-if="report" class="grid gap-4">
      <Card>
        <div class="flex items-center gap-3 flex-wrap">
          <div>
            <div class="text-base font-semibold">{{ report.framework_label }}</div>
            <div class="text-xs text-dim">version {{ report.framework_version }} &middot; {{ report.framework_type }}</div>
          </div>
          <div class="ml-auto grid grid-cols-3 sm:grid-cols-6 gap-2 text-center">
            <div><div class="text-lg font-semibold">{{ sum.total }}</div><div class="text-[10px] text-dim uppercase">total</div></div>
            <div><div class="text-lg font-semibold text-accent">{{ sum.applicable }}</div><div class="text-[10px] text-dim uppercase">applicable</div></div>
            <div><div class="text-lg font-semibold text-ok">{{ sum.conformant }}</div><div class="text-[10px] text-dim uppercase">conformant</div></div>
            <div><div class="text-lg font-semibold text-warn">{{ sum.partial }}</div><div class="text-[10px] text-dim uppercase">partial</div></div>
            <div><div class="text-lg font-semibold text-ver">{{ sum.not_assessed }}</div><div class="text-[10px] text-dim uppercase">to assess</div></div>
            <div><div class="text-lg font-semibold text-dim">{{ sum.not_applicable }}</div><div class="text-[10px] text-dim uppercase">N/A</div></div>
          </div>
        </div>
      </Card>

      <Card title="Controls" :subtitle="`${(report.controls||[]).length} controls`">
        <DataTable :columns="['Reference','Control','Type','Conformity','Note']">
          <tr v-for="c in report.controls" :key="c.control_id" class="border-b border-line/60">
            <td class="py-2 pr-4 font-mono text-xs whitespace-nowrap">{{ c.reference || c.control_id }}</td>
            <td class="py-2 pr-4">{{ c.title }}</td>
            <td class="py-2 pr-4 text-dim text-xs">{{ c.obligation_type }}</td>
            <td class="py-2 pr-4"><Badge :kind="cmark(c.conformity)">{{ c.conformity }}</Badge></td>
            <td class="py-2 pr-4 text-dim text-xs">{{ c.applicable ? '' : c.exclusion_reason }}</td>
          </tr>
        </DataTable>
      </Card>
    </div>
  </div>
</template>
