<script setup>
import { ref, onMounted } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'
import RowActions from '../components/ui/RowActions.vue'

const { data, refresh } = usePoll(async () => asList(await getOr('/agents', { agents: [] }), 'agents'))
const apps = ref([])
const showAdd = ref(false); const editId = ref(null)
const blank = () => ({ app_id: '', name: '', type: 'Custom / in-house', domain: '', tools: '', environment: 'prod', owner: '', description: '' })
const form = ref(blank())
const err = ref(''); const token = ref(''); const assessMsg = ref('')

const TYPES = ['Claude Code', 'GitHub Copilot', 'Cursor', 'LangChain / framework', 'Custom / in-house', 'Other']
async function loadApps() { apps.value = asList(await getOr('/apps', { apps: [] }), 'apps') }
function meta(a) { try { return JSON.parse(a.metadata_json || '{}') } catch { return {} } }

function openNew() { form.value = blank(); editId.value = null; err.value = ''; token.value = ''; showAdd.value = true; loadApps() }
function openEdit(a) {
  const m = meta(a)
  form.value = { app_id: a.app_id || '', name: a.name || '', type: m.type || 'Custom / in-house', domain: m.domain || '', tools: (m.tools || []).join(', '), environment: m.environment || 'prod', owner: a.owner || '', description: m.description || '' }
  editId.value = a.id; err.value = ''; token.value = ''; showAdd.value = true; loadApps()
}
async function save() {
  err.value = ''; token.value = ''
  if (!form.value.app_id) { err.value = 'Pick an application.'; return }
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  const metadata = { type: form.value.type, domain: form.value.domain.trim(), tools: form.value.tools.split(',').map(s => s.trim()).filter(Boolean), environment: form.value.environment, description: form.value.description.trim() }
  try {
    if (editId.value) { await post(`/agents/${editId.value}/update`, { name: form.value.name.trim(), owner: form.value.owner, metadata }, 'AppRegistrar'); showAdd.value = false; await refresh() }
    else { const r = await post('/agents', { app_id: form.value.app_id, name: form.value.name.trim(), owner: form.value.owner, metadata }, 'AppRegistrar'); token.value = r.token || ''; showAdd.value = false; await refresh() }
  } catch (e) { err.value = String(e.message || e) }
}
async function del(a) {
  if (!confirm(`Delete agent "${a.name || a.id}"?`)) return
  try { await post(`/agents/${a.id}/delete`, {}, 'AppRegistrar'); await refresh() } catch (e) { err.value = String(e.message || e) }
}
async function autoAssess(id) {
  assessMsg.value = ''
  try { const r = await post(`/agents/${id}/auto-assess`, {}, 'GrcAuthor'); assessMsg.value = r.ok ? `Auto-assessed "${id}": proposed tier ${r.tier || '(see Governance)'}.` : (r.error || 'auto-assess failed') } catch (e) { assessMsg.value = String(e.message || e) }
}
function tierKind(t) { return { high: 'bad', limited: 'warn', minimal: 'ok', unacceptable: 'bad' }[t] || 'muted' }
onMounted(loadApps)
</script>
<template>
  <Card title="Agents" subtitle="governed AI agent identities">
    <template #cta><Btn size="sm" @click="openNew">New agent</Btn></template>
    <p class="text-xs text-dim mb-3">
      An agent is a specific AI agent deployment governed by the control plane, running under an application.
      It may be an instance of a product (Claude Code, Copilot, Cursor) or an in-house agent. Registering it
      issues a one-time credential so every tool and model call it makes is verified, authorised, logged, and
      attributed to the human it acts for.
    </p>

    <Modal v-if="showAdd" :title="editId ? 'Edit agent' : 'New agent'" wide @close="showAdd = false">
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="text-xs text-dim">Application
          <select v-model="form.app_id" :disabled="!!editId" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm disabled:opacity-60">
            <option value="">select app…</option>
            <option v-for="a in apps" :key="a.id" :value="a.id">{{ a.name }} ({{ a.id }})</option>
          </select>
        </label>
        <label class="text-xs text-dim">Agent name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. Resume Screener" /></label>
        <label class="text-xs text-dim">Type / product
          <select v-model="form.type" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option v-for="t in TYPES" :key="t" :value="t">{{ t }}</option></select>
        </label>
        <label class="text-xs text-dim">Environment
          <select v-model="form.environment" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option value="prod">prod</option><option value="staging">staging</option><option value="dev">dev</option></select>
        </label>
        <label class="text-xs text-dim">Business domain <span class="text-muted">(feeds auto risk-tiering)</span>
          <input v-model="form.domain" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. hr, finance, support" />
        </label>
        <label class="text-xs text-dim">Tool bindings <span class="text-muted">(comma-separated)</span>
          <input v-model="form.tools" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. resume.parse, candidate.rank" />
        </label>
        <label class="text-xs text-dim">Owner<input v-model="form.owner" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="team / owner" /></label>
        <label class="text-xs text-dim">Description<input v-model="form.description" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="what it does" /></label>
        <div class="col-span-full flex justify-end pt-1"><Btn @click="save">{{ editId ? 'Save' : 'Register agent' }}</Btn></div>
      </div>
    </Modal>

    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="assessMsg" class="text-ok text-sm mb-2">{{ assessMsg }}</p>
    <div v-if="token" class="mb-3 p-3 border border-ok/40 bg-ok/10 rounded-lg text-sm">
      <div class="text-ok font-medium">Agent registered. One-time token (store it now, it is not shown again):</div>
      <code class="font-mono text-xs break-all">{{ token }}</code>
    </div>

    <DataTable :columns="['Name','Type','App','Domain','Env','Status','']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4"><div>{{ a.name || '-' }}</div><div class="font-mono text-[10px] text-muted">{{ a.id }}</div></td>
        <td class="py-2 pr-4">{{ meta(a).type || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.app || a.app_id || '-' }}</td>
        <td class="py-2 pr-4">{{ meta(a).domain || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ meta(a).environment || '-' }}</td>
        <td class="py-2 pr-4"><Badge :kind="(a.status==='active'||a.active) ? 'ok' : 'muted'">{{ a.status || (a.active ? 'active' : '-') }}</Badge></td>
        <td class="py-2 pr-4">
          <div class="flex justify-end items-center gap-1">
            <Btn size="sm" variant="ghost" @click="autoAssess(a.id)" title="Propose an EU AI Act risk tier from domain + tools">Auto-assess</Btn>
            <RowActions @edit="openEdit(a)" @delete="del(a)" />
          </div>
        </td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="7" class="py-6 text-center text-dim">No agents registered.</td></tr>
    </DataTable>
  </Card>
</template>
