<script setup>
import { ref, onMounted } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
const { data, refresh } = usePoll(async () => asList(await getOr('/agents', { agents: [] }), 'agents'))
const apps = ref([])
const showAdd = ref(false); const form = ref({ app_id: '', name: '' }); const err = ref(''); const token = ref('')
async function loadApps() { apps.value = asList(await getOr('/apps', { apps: [] }), 'apps') }
async function add() {
  err.value = ''; token.value = ''
  if (!form.value.app_id) { err.value = 'Pick an application.'; return }
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  try {
    const r = await post('/agents', { app_id: form.value.app_id, name: form.value.name.trim() }, 'AppRegistrar')
    token.value = r.token || ''; form.value = { app_id: '', name: '' }; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
function tier(t) { return { high: 'bad', limited: 'warn', minimal: 'ok', unacceptable: 'bad' }[t] || 'muted' }
onMounted(loadApps)
</script>
<template>
  <Card title="Agents" subtitle="registered agent identities">
    <template #cta><Btn size="sm" @click="showAdd = !showAdd; if (showAdd) loadApps()">{{ showAdd ? 'Cancel' : 'New agent' }}</Btn></template>
    <div v-if="showAdd" class="grid sm:grid-cols-[1fr_1fr_auto] gap-2 items-end mb-4 p-3 border border-line rounded-lg">
      <label class="text-xs text-dim">Application
        <select v-model="form.app_id" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
          <option value="">select app…</option>
          <option v-for="a in apps" :key="a.id" :value="a.id">{{ a.name }} ({{ a.id }})</option>
        </select>
      </label>
      <label class="text-xs text-dim">Agent name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. Resume Screener" /></label>
      <Btn size="sm" @click="add">Register</Btn>
    </div>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <div v-if="token" class="mb-3 p-3 border border-ok/40 bg-ok/10 rounded-lg text-sm">
      <div class="text-ok font-medium">Agent registered. One-time token (store it now, it is not shown again):</div>
      <code class="font-mono text-xs break-all">{{ token }}</code>
    </div>
    <DataTable :columns="['ID','Name','App','Risk tier','Status']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.id }}</td>
        <td class="py-2 pr-4">{{ a.name || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.app || a.app_id || '-' }}</td>
        <td class="py-2 pr-4"><Badge v-if="a.tier||a.risk_tier" :kind="tier(a.tier||a.risk_tier)">{{ a.tier || a.risk_tier }}</Badge><span v-else class="text-dim">-</span></td>
        <td class="py-2 pr-4"><Badge :kind="(a.status==='active'||a.active) ? 'ok' : 'muted'">{{ a.status || (a.active ? 'active' : '-') }}</Badge></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="5" class="py-6 text-center text-dim">No agents registered.</td></tr>
    </DataTable>
  </Card>
</template>
