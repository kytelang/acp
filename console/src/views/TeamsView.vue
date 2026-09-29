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
const { data, refresh } = usePoll(async () => asList(await getOr('/apps', { apps: [] }), 'apps'))
const showAdd = ref(false); const editId = ref(null)
const blank = () => ({ name: '', owner: '', description: '', environment: 'prod' })
const form = ref(blank()); const err = ref(''); const msg = ref('')
function meta(a) { try { return JSON.parse(a.metadata_json || '{}') } catch { return {} } }
function openNew() { form.value = blank(); editId.value = null; err.value = ''; showAdd.value = true }
function openEdit(a) { const m = meta(a); form.value = { name: a.name || '', owner: a.owner || '', description: m.description || '', environment: m.environment || 'prod' }; editId.value = a.id; err.value = ''; showAdd.value = true }
async function save() {
  err.value = ''
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  const body = { name: form.value.name.trim(), owner: form.value.owner, metadata: { description: form.value.description.trim(), environment: form.value.environment } }
  try {
    if (editId.value) await post(`/apps/${editId.value}/update`, body, 'AppRegistrar')
    else await post('/apps', body, 'AppRegistrar')
    showAdd.value = false; msg.value = editId.value ? 'Team updated.' : 'Team registered.'; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
async function del(a) {
  if (!confirm(`Delete team "${a.name || a.id}"?`)) return
  try { await post(`/apps/${a.id}/delete`, {}, 'AppRegistrar'); await refresh() } catch (e) { err.value = String(e.message || e) }
}
</script>
<template>
  <Card title="Teams / applications" subtitle="the applications/services that own agents (the PEP boundary)">
    <template #cta><Btn size="sm" @click="openNew">New team</Btn></template>
    <Modal v-if="showAdd" :title="editId ? 'Edit team' : 'New team'" @close="showAdd = false">
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-xs text-dim">Name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. HR Portal" /></label>
        <label class="text-xs text-dim">Owner<input v-model="form.owner" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="team / owner" /></label>
        <label class="text-xs text-dim">Environment
          <select v-model="form.environment" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option value="prod">prod</option><option value="staging">staging</option><option value="dev">dev</option></select>
        </label>
        <label class="text-xs text-dim">Description<input v-model="form.description" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="what this application is" /></label>
        <div class="col-span-full flex justify-end pt-1"><Btn @click="save">{{ editId ? 'Save' : 'Register' }}</Btn></div>
      </div>
    </Modal>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="msg" class="text-ok text-sm mb-2">{{ msg }}</p>
    <DataTable :columns="['ID','Name','Owner','Status','']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.id }}</td>
        <td class="py-2 pr-4">{{ a.name || a.title || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.owner || a.team || '-' }}</td>
        <td class="py-2 pr-4"><Badge :kind="(a.status==='active'||a.active) ? 'ok' : 'muted'">{{ a.status || (a.active ? 'active' : '-') }}</Badge></td>
        <td class="py-2 pr-4"><RowActions @edit="openEdit(a)" @delete="del(a)" /></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="5" class="py-6 text-center text-dim">No applications registered.</td></tr>
    </DataTable>
  </Card>
</template>
