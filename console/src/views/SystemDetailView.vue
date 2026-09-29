<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get, getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const route = useRoute(); const router = useRouter()
const id = route.params.id
const sys = ref(null); const roles = ref([])
const frameworks = ref([])
const framework = ref('eu-ai-act')
const soa = ref([])              // worksheet rows (editable)
const report = ref(null)
const roleForm = ref({ role: 'deployer', jurisdiction: '' })
const err = ref(''); const msg = ref('')
const STATUS = ['planned', 'implemented', 'partial', 'gap', 'not-applicable']

async function loadSystem() {
  const d = await getOr(`/systems/${id}`, {})
  sys.value = d.system || null; roles.value = d.roles || []
}
async function loadFrameworks() {
  const t = await getOr('/grc/templates', { templates: [] })
  frameworks.value = (t.templates || []).filter(x => x.kind === 'checklist').map(x => ({ slug: x.framework, name: x.name }))
}
async function loadSoa() {
  err.value = ''
  const d = await getOr(`/systems/${id}/soa/${framework.value}`, { entries: [] })
  soa.value = d.entries || []
  report.value = await getOr(`/systems/${id}/report/${framework.value}`, null)
}
async function saveSoa() {
  err.value = ''; msg.value = ''
  const entries = soa.value.map(e => ({ control_id: e.control_id, applicable: e.applicable, justification: e.justification, status: e.status }))
  try { await post(`/systems/${id}/soa/${framework.value}`, { entries }, 'GrcAuthor'); msg.value = 'Statement of Applicability saved.'; await loadSoa() }
  catch (e) { err.value = String(e.message || e) }
}
async function addRole() {
  err.value = ''
  if (!roleForm.value.role) return
  try { await post(`/systems/${id}/roles`, roleForm.value, 'GrcAuthor'); roleForm.value = { role: 'deployer', jurisdiction: '' }; await loadSystem() }
  catch (e) { err.value = String(e.message || e) }
}
const sum = computed(() => report.value?.conformity_summary || {})
function cmark(c) { return { conformant: 'ok', partial: 'warn', 'non-conformant': 'bad', 'not-applicable': 'muted', 'not-assessed': 'ver' }[c] || 'muted' }
onMounted(async () => { await loadSystem(); await loadFrameworks(); await loadSoa() })
</script>
<template>
  <div class="grid gap-4">
    <div class="flex items-center gap-2">
      <Btn size="sm" variant="ghost" @click="router.push('/systems')">&larr; Systems</Btn>
      <h2 v-if="sys" class="text-base font-semibold">{{ sys.name }}</h2>
    </div>

    <Card v-if="sys" title="System" :subtitle="sys.id">
      <div class="grid sm:grid-cols-4 gap-3 text-sm">
        <div><div class="text-xs text-dim uppercase">Owner</div>{{ sys.owner || '-' }}</div>
        <div><div class="text-xs text-dim uppercase">Risk tier</div><Badge :kind="sys.risk_tier==='high'?'bad':sys.risk_tier?'warn':'muted'">{{ sys.risk_tier || '-' }}</Badge></div>
        <div><div class="text-xs text-dim uppercase">Sector</div>{{ sys.sector || '-' }}</div>
        <div><div class="text-xs text-dim uppercase">Lifecycle</div>{{ sys.lifecycle_state }}</div>
      </div>
      <div v-if="sys.purpose" class="mt-2 text-sm text-dim">{{ sys.purpose }}</div>
    </Card>

    <Card title="Roles" subtitle="the role you play per jurisdiction (drives applicability)">
      <DataTable :columns="['Role','Jurisdiction','Market date']">
        <tr v-for="r in roles" :key="r.id" class="border-b border-line/60">
          <td class="py-2 pr-4"><Badge kind="ver">{{ r.role }}</Badge></td>
          <td class="py-2 pr-4">{{ r.jurisdiction || '-' }}</td>
          <td class="py-2 pr-4 text-dim">{{ r.market_date || '-' }}</td>
        </tr>
        <tr v-if="!roles.length"><td colspan="3" class="py-4 text-center text-dim">No roles declared.</td></tr>
      </DataTable>
      <div class="grid sm:grid-cols-[1fr_1fr_auto] gap-2 items-end mt-3">
        <label class="text-xs text-dim">Role
          <select v-model="roleForm.role" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option>provider</option><option>deployer</option><option>importer</option><option>distributor</option></select>
        </label>
        <label class="text-xs text-dim">Jurisdiction<input v-model="roleForm.jurisdiction" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. UK, EU" /></label>
        <Btn size="sm" @click="addRole">Add role</Btn>
      </div>
    </Card>

    <Card title="Statement of Applicability" subtitle="per framework: which controls apply, why, and their status">
      <div class="flex items-center gap-3 mb-3">
        <label class="text-xs text-dim">Framework
          <select v-model="framework" @change="loadSoa" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm min-w-56">
            <option v-for="f in frameworks" :key="f.slug" :value="f.slug">{{ f.name }}</option>
          </select>
        </label>
        <div v-if="report" class="ml-auto flex gap-2 text-center text-xs">
          <div><div class="text-base font-semibold text-ok">{{ sum.conformant }}</div>conformant</div>
          <div><div class="text-base font-semibold text-warn">{{ sum.partial }}</div>partial</div>
          <div><div class="text-base font-semibold text-ver">{{ sum.not_assessed }}</div>to assess</div>
          <div><div class="text-base font-semibold text-dim">{{ sum.not_applicable }}</div>N/A</div>
        </div>
      </div>
      <div class="max-h-[28rem] overflow-y-auto">
        <DataTable :columns="['Reference','Control','Applicable','Status','Justification']">
          <tr v-for="e in soa" :key="e.control_id" class="border-b border-line/60">
            <td class="py-1.5 pr-4 font-mono text-xs whitespace-nowrap">{{ e.reference || e.control_id }}</td>
            <td class="py-1.5 pr-4">{{ e.title }}</td>
            <td class="py-1.5 pr-4"><input type="checkbox" v-model="e.applicable" /></td>
            <td class="py-1.5 pr-4">
              <select v-model="e.status" :disabled="!e.applicable" class="bg-panel2 border border-line rounded-md px-1.5 py-1 text-xs">
                <option v-for="s in STATUS" :key="s" :value="s">{{ s }}</option>
              </select>
            </td>
            <td class="py-1.5 pr-4"><input v-model="e.justification" class="bg-panel2 border border-line rounded-md px-1.5 py-1 text-xs w-full" :placeholder="e.applicable ? 'optional' : 'why excluded'" /></td>
          </tr>
        </DataTable>
      </div>
      <div class="flex items-center gap-3 mt-3">
        <Btn @click="saveSoa">Save Statement of Applicability</Btn>
        <span v-if="msg" class="text-ok text-sm">{{ msg }}</span>
        <span v-if="err" class="text-bad text-sm">{{ err }}</span>
      </div>
    </Card>
  </div>
</template>
