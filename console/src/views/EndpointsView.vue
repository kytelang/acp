<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
const { data, refresh } = usePoll(async () => asList(await getOr('/endpoints', { endpoints: [] }), 'endpoints'))
const showAdd = ref(false); const form = ref({ endpoint: '', disposition: 'govern', reason: '' }); const err = ref(''); const msg = ref('')
async function add() {
  err.value = ''
  if (!form.value.endpoint.trim()) { err.value = 'Endpoint URL/host is required.'; return }
  try {
    await post('/endpoints/register', { endpoint: form.value.endpoint.trim(), disposition: form.value.disposition, reason: form.value.reason }, 'PolicyAdmin')
    form.value = { endpoint: '', disposition: 'govern', reason: '' }; showAdd.value = false; msg.value = 'Endpoint registered.'; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
function dkind(d) { return d === 'block' ? 'bad' : d === 'govern' ? 'ok' : 'warn' }
</script>
<template>
  <Card title="AI endpoints" subtitle="registered model API endpoints (LLM gateway)">
    <template #cta><Btn size="sm" @click="showAdd = !showAdd">{{ showAdd ? 'Cancel' : 'New endpoint' }}</Btn></template>
    <div v-if="showAdd" class="grid sm:grid-cols-[1.4fr_0.8fr_1fr_auto] gap-2 items-end mb-4 p-3 border border-line rounded-lg">
      <label class="text-xs text-dim">Endpoint (URL or host)<input v-model="form.endpoint" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. https://api.openai.com" /></label>
      <label class="text-xs text-dim">Disposition
        <select v-model="form.disposition" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
          <option value="govern">govern</option><option value="block">block</option><option value="accept-risk">accept-risk</option>
        </select>
      </label>
      <label class="text-xs text-dim">Reason<input v-model="form.reason" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="optional" /></label>
      <Btn size="sm" @click="add">Register</Btn>
    </div>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="msg" class="text-ok text-sm mb-2">{{ msg }}</p>
    <DataTable :columns="['Endpoint','Provider','Kind','Disposition','Status']">
      <tr v-for="(e,i) in (data||[])" :key="i" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs truncate max-w-xs">{{ e.endpoint || e.url || '-' }}</td>
        <td class="py-2 pr-4">{{ e.provider || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ e.kind || e.class || '-' }}</td>
        <td class="py-2 pr-4"><Badge :kind="dkind(e.disposition)">{{ e.disposition || '-' }}</Badge></td>
        <td class="py-2 pr-4"><Badge :kind="e.active ? 'ok' : 'muted'">{{ e.active ? 'active' : 'inactive' }}</Badge></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="5" class="py-6 text-center text-dim">No endpoints registered.</td></tr>
    </DataTable>
  </Card>
</template>
