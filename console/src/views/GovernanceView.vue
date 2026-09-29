<script setup>
import { ref, onMounted, computed } from 'vue'
import { get, getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'

const records = ref([])
const frameworks = ref([])
const euQuestions = ref([])
const showAssess = ref(false)
const msg = ref(''); const err = ref('')
const form = ref({ subject: '', framework: 'eu-ai-act', answers: {} })

async function load() {
  const r = await getOr('/grc', { records: [] })
  records.value = Array.isArray(r) ? r : (r.records || [])
  const t = await getOr('/grc/templates', { templates: [] })
  frameworks.value = (t.templates || []).filter(x => x.kind === 'checklist').map(x => ({ slug: x.framework, name: x.name }))
  const eu = (t.templates || []).find(x => x.id === 'eu-ai-act-screening')
  euQuestions.value = eu?.questions || []
}
function openAssess() { form.value = { subject: '', framework: 'eu-ai-act', answers: {} }; msg.value = ''; err.value = ''; showAssess.value = true }
async function submitAssess() {
  err.value = ''
  if (!form.value.subject.trim()) { err.value = 'System name is required.'; return }
  try {
    await post('/grc/assess', { subject: form.value.subject.trim(), framework: form.value.framework, answers: form.value.answers }, 'GrcAuthor')
    showAssess.value = false; msg.value = 'Assessment created.'; await load()
  } catch (e) { err.value = String(e.message || e) }
}
function stkind(s) { return s === 'signed' || s === 'approved' || s === 'done' ? 'ok' : s === 'open' ? 'warn' : 'muted' }
const byKind = computed(() => {
  const m = {}
  for (const r of records.value) m[r.kind || 'other'] = (m[r.kind || 'other'] || 0) + 1
  return m
})
onMounted(load)
</script>
<template>
  <div class="grid gap-4">
    <div class="flex items-center gap-3">
      <div class="flex gap-2 flex-wrap">
        <Badge v-for="(n,k) in byKind" :key="k" kind="ver">{{ k }}: {{ n }}</Badge>
        <Badge v-if="!records.length" kind="muted">no records</Badge>
      </div>
      <div class="ml-auto"><Btn @click="openAssess">New assessment</Btn></div>
    </div>
    <p v-if="msg" class="text-ok text-sm">{{ msg }}</p>

    <Card title="Governance records" subtitle="assessments, risks, model cards, use cases, incidents">
      <DataTable :columns="['ID','Kind','Subject','Title','Status']">
        <tr v-for="r in records" :key="r.id" class="border-b border-line/60">
          <td class="py-2 pr-4 font-mono text-xs">{{ r.id }}</td>
          <td class="py-2 pr-4">{{ r.kind }}</td>
          <td class="py-2 pr-4">{{ r.subject }}</td>
          <td class="py-2 pr-4 text-dim">{{ r.title }}</td>
          <td class="py-2 pr-4"><Badge :kind="stkind(r.status)">{{ r.status }}</Badge></td>
        </tr>
        <tr v-if="!records.length"><td colspan="5" class="py-6 text-center text-dim">No governance records yet.</td></tr>
      </DataTable>
    </Card>

    <Modal v-if="showAssess" title="New assessment" @close="showAssess=false">
      <div class="grid gap-3">
        <label class="text-xs text-dim">AI system
          <input v-model="form.subject" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="system name" />
        </label>
        <label class="text-xs text-dim">Framework
          <select v-model="form.framework" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option v-for="f in frameworks" :key="f.slug" :value="f.slug">{{ f.name }}</option>
          </select>
        </label>
        <div v-if="form.framework==='eu-ai-act'" class="grid gap-1.5 border border-line rounded-lg p-3">
          <div class="text-xs text-dim mb-1">EU AI Act risk screening</div>
          <label v-for="q in euQuestions" :key="q.key" class="flex items-start gap-2 text-[13px]">
            <input type="checkbox" v-model="form.answers[q.key]" class="mt-1" /> <span>{{ q.label }}</span>
          </label>
        </div>
        <p v-else class="text-dim text-xs">Conformity checklist assessment for this framework will enumerate its applicable controls.</p>
        <div class="flex items-center gap-3">
          <Btn @click="submitAssess">Create</Btn>
          <span v-if="err" class="text-bad text-sm">{{ err }}</span>
        </div>
      </div>
    </Modal>
  </div>
</template>
