<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { getOr, post } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'
import RowActions from '../components/ui/RowActions.vue'

const router = useRouter()
const { data, refresh } = usePoll(async () => (await getOr('/systems', { systems: [] })).systems || [])
const showAdd = ref(false); const editId = ref(null)
const blank = () => ({ name: '', purpose: '', owner: '', risk_tier: 'high', sector: '', asset_type: '', jurisdictions: '' })
const form = ref(blank()); const err = ref('')
function openNew() { form.value = blank(); editId.value = null; err.value = ''; showAdd.value = true }
function openEdit(s) {
  form.value = { name: s.name || '', purpose: s.purpose || '', owner: s.owner || '', risk_tier: s.risk_tier || 'high', sector: s.sector || '', asset_type: s.asset_type || '', jurisdictions: (() => { try { return (JSON.parse(s.jurisdictions || '[]')).join(', ') } catch { return '' } })() }
  editId.value = s.id; err.value = ''; showAdd.value = true
}
async function save() {
  err.value = ''
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  const body = { ...form.value, jurisdictions: form.value.jurisdictions.split(',').map(s => s.trim()).filter(Boolean) }
  try {
    if (editId.value) { await post(`/systems/${editId.value}/update`, body, 'GrcAuthor'); showAdd.value = false; await refresh() }
    else { const r = await post('/systems', body, 'GrcAuthor'); showAdd.value = false; await refresh(); if (r.id) router.push(`/systems/${r.id}`) }
  } catch (e) { err.value = String(e.message || e) }
}
async function del(s) {
  if (!confirm(`Delete AI system "${s.name}" and all its roles, SoA, evidence and history?`)) return
  try { await post(`/systems/${s.id}/delete`, {}, 'GrcAuthor'); await refresh() } catch (e) { err.value = String(e.message || e) }
}
function tierKind(t) { return { high: 'bad', limited: 'warn', minimal: 'ok', unacceptable: 'bad' }[t] || 'muted' }
</script>
<template>
  <Card title="AI systems" subtitle="the governed AI estate (first-class use-case registry)">
    <template #cta><Btn size="sm" @click="openNew">New system</Btn></template>
    <p class="text-xs text-dim mb-3">
      An AI system (use case) is the anchor for governance: roles, assessments, risks, evidence and reports
      all hang off it. Register a system, declare the roles you play per jurisdiction, then work its Statement
      of Applicability per framework.
    </p>
    <Modal v-if="showAdd" :title="editId ? 'Edit AI system' : 'New AI system'" @close="showAdd = false">
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-xs text-dim">Name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. Resume Screener" /></label>
        <label class="text-xs text-dim">Owner<input v-model="form.owner" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="team / owner" /></label>
        <label class="text-xs text-dim">Risk tier
          <select v-model="form.risk_tier" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option>high</option><option>limited</option><option>minimal</option><option>unacceptable</option></select>
        </label>
        <label class="text-xs text-dim">Sector<input v-model="form.sector" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. hr, finance" /></label>
        <label class="text-xs text-dim">Jurisdictions (comma-separated)<input v-model="form.jurisdictions" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. UK, EU" /></label>
        <label class="text-xs text-dim">Purpose<input v-model="form.purpose" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="intended purpose" /></label>
        <div class="col-span-full flex justify-end pt-1"><Btn @click="save">{{ editId ? 'Save' : 'Register system' }}</Btn></div>
      </div>
    </Modal>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <DataTable :columns="['Name','Owner','Risk tier','Sector','Lifecycle','']">
      <tr v-for="s in (data||[])" :key="s.id" class="border-b border-line/60 hover:bg-panel2/50">
        <td class="py-2 pr-4 cursor-pointer" @click="router.push(`/systems/${s.id}`)"><div>{{ s.name }}</div><div class="font-mono text-[10px] text-muted">{{ s.id }}</div></td>
        <td class="py-2 pr-4 text-dim">{{ s.owner || '-' }}</td>
        <td class="py-2 pr-4"><Badge v-if="s.risk_tier" :kind="tierKind(s.risk_tier)">{{ s.risk_tier }}</Badge><span v-else class="text-dim">-</span></td>
        <td class="py-2 pr-4">{{ s.sector || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ s.lifecycle_state }}</td>
        <td class="py-2 pr-4">
          <div class="flex justify-end items-center gap-1">
            <Btn size="sm" variant="ghost" @click.stop="router.push(`/systems/${s.id}`)">Open</Btn>
            <RowActions @edit="openEdit(s)" @delete="del(s)" />
          </div>
        </td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="6" class="py-6 text-center text-dim">No AI systems registered.</td></tr>
    </DataTable>
  </Card>
</template>
