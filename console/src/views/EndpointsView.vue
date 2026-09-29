<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'
import RowActions from '../components/ui/RowActions.vue'
const { data, refresh } = usePoll(async () => asList(await getOr('/endpoints', { endpoints: [] }), 'endpoints'))
const showAdd = ref(false); const editId = ref(null)
const blank = () => ({ endpoint: '', disposition: 'govern', reason: '' })
const form = ref(blank()); const err = ref(''); const msg = ref('')
function openNew() { form.value = blank(); editId.value = null; err.value = ''; showAdd.value = true }
function openEdit(e) { form.value = { endpoint: e.endpoint || '', disposition: e.disposition || 'govern', reason: e.reason || '' }; editId.value = e.endpoint; err.value = ''; showAdd.value = true }
async function save() {
  err.value = ''
  if (!form.value.endpoint.trim()) { err.value = 'Endpoint URL/host is required.'; return }
  try {
    // register is an upsert, so it serves both create and edit (the endpoint host is the key).
    await post('/endpoints/register', { endpoint: form.value.endpoint.trim(), disposition: form.value.disposition, reason: form.value.reason }, 'PolicyAdmin')
    showAdd.value = false; msg.value = editId.value ? 'Endpoint updated.' : 'Endpoint registered.'; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
async function del(e) {
  if (!confirm(`Delete endpoint "${e.endpoint}"?`)) return
  try { await post('/endpoints/delete', { endpoint: e.endpoint }, 'PolicyAdmin'); await refresh() } catch (er) { err.value = String(er.message || er) }
}
function dkind(d) { return d === 'block' ? 'bad' : d === 'govern' ? 'ok' : 'warn' }
</script>
<template>
  <Card title="AI endpoints" subtitle="registered model API endpoints (LLM gateway)">
    <template #cta><Btn size="sm" @click="openNew">New endpoint</Btn></template>
    <Modal v-if="showAdd" :title="editId ? 'Edit endpoint' : 'New AI endpoint'" @close="showAdd = false">
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-xs text-dim sm:col-span-2">Endpoint (URL or host)<input v-model="form.endpoint" :disabled="!!editId" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm disabled:opacity-60" placeholder="e.g. https://api.openai.com" /></label>
        <label class="text-xs text-dim">Disposition
          <select v-model="form.disposition" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option value="govern">govern</option><option value="block">block</option><option value="accept-risk">accept-risk</option>
          </select>
        </label>
        <label class="text-xs text-dim">Reason<input v-model="form.reason" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="optional" /></label>
        <div class="col-span-full flex justify-end pt-1"><Btn @click="save">{{ editId ? 'Save' : 'Register' }}</Btn></div>
      </div>
    </Modal>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="msg" class="text-ok text-sm mb-2">{{ msg }}</p>
    <DataTable :columns="['Endpoint','Provider','Kind','Disposition','Status','']">
      <tr v-for="(e,i) in (data||[])" :key="i" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs truncate max-w-xs">{{ e.endpoint || e.url || '-' }}</td>
        <td class="py-2 pr-4">{{ e.provider || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ e.kind || e.class || '-' }}</td>
        <td class="py-2 pr-4"><Badge :kind="dkind(e.disposition)">{{ e.disposition || '-' }}</Badge></td>
        <td class="py-2 pr-4"><Badge :kind="e.active ? 'ok' : 'muted'">{{ e.active ? 'active' : 'inactive' }}</Badge></td>
        <td class="py-2 pr-4"><RowActions @edit="openEdit(e)" @delete="del(e)" /></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="6" class="py-6 text-center text-dim">No endpoints registered.</td></tr>
    </DataTable>
  </Card>
</template>
