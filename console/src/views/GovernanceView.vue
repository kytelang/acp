<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
import Modal from '../components/ui/Modal.vue'

const router = useRouter()
const records = ref([])
const frameworks = ref([])
const templates = ref([])   // full per-framework checklist templates (with control items)
const checked = ref({})      // control_id -> done, for a non-EU conformity assessment
const selected = ref(null)     // selected system name
const tab = ref('all')
const modal = ref(null)        // 'assess' | 'risk' | 'modelcard'
const msg = ref(''); const err = ref('')

const assessForm = ref({ subject: '', framework: 'eu-ai-act' })
const riskForm = ref({ subject: '', title: '', likelihood: 'medium', impact: 'medium', treatment: 'mitigate', owner: '' })
const cardForm = ref({ subject: '', title: '', model_id: '', use_case_id: '', risk_id: '', summary: '' })

async function load() {
  const r = await getOr('/grc', { records: [] })
  records.value = Array.isArray(r) ? r : (r.records || [])
  const t = await getOr('/grc/templates', { templates: [] })
  templates.value = (t.templates || []).filter(x => x.kind === 'checklist')
  frameworks.value = templates.value.map(x => ({ slug: x.framework, name: x.name }))
}

// The AI-system registry is the hub: records grouped by their subject (the system / use case).
const systems = computed(() => {
  const m = new Map()
  for (const r of records.value) {
    const key = r.subject || '(unassigned)'
    if (!m.has(key)) m.set(key, { name: key, records: [], kinds: {} })
    const s = m.get(key)
    s.records.push(r)
    s.kinds[r.kind || 'other'] = (s.kinds[r.kind || 'other'] || 0) + 1
  }
  return [...m.values()].sort((a, b) => a.name.localeCompare(b.name))
})
const current = computed(() => systems.value.find(s => s.name === selected.value) || null)
// The control set for the framework selected in the assessment modal (non-EU conformity checklist).
const frameworkControls = computed(() => {
  const t = templates.value.find(x => x.framework === assessForm.value.framework)
  return t ? (t.items || []) : []
})
function frameworkName(slug) { return (frameworks.value.find(f => f.slug === slug) || {}).name || slug }
const currentRecords = computed(() => {
  if (!current.value) return []
  if (tab.value === 'all') return current.value.records
  const map = { assessments: ['assessment', 'conformity'], risks: ['risk'], cards: ['model-card'] }
  const kinds = map[tab.value] || []
  return current.value.records.filter(r => kinds.includes(r.kind))
})

function openAssess() { assessForm.value = { subject: selected.value || '', framework: 'eu-ai-act' }; checked.value = {}; err.value=''; modal.value = 'assess' }
function openRisk() { riskForm.value = { subject: selected.value || '', title: '', likelihood: 'medium', impact: 'medium', treatment: 'mitigate', owner: '' }; err.value=''; modal.value = 'risk' }
function openCard() { cardForm.value = { subject: selected.value || '', title: '', model_id: '', use_case_id: '', risk_id: '', summary: '' }; err.value=''; modal.value = 'modelcard' }

async function submit(kind) {
  err.value = ''
  try {
    if (kind === 'assess') {
      const subject = assessForm.value.subject.trim()
      if (!subject) throw new Error('System name is required.')
      const fw = assessForm.value.framework
      // Every framework creates a conformity record over its full control set, which the framework
      // report then grades. The risk tier lives on the AI system itself (drives applicability).
      const checklist = frameworkControls.value.map(c => ({
        control_id: c.control_id, reference: c.reference, title: c.title, done: !!checked.value[c.control_id]
      }))
      await post('/grc', { kind: 'conformity', subject, title: `${frameworkName(fw)} conformity`, status: 'open', body: { framework: fw, checklist } }, 'GrcAuthor')
    } else if (kind === 'risk') {
      if (!riskForm.value.subject.trim()) throw new Error('System name is required.')
      await post('/grc/risk', riskForm.value, 'GrcAuthor')
    } else {
      if (!cardForm.value.subject.trim()) throw new Error('System name is required.')
      await post('/grc/model-card', cardForm.value, 'GrcAuthor')
    }
    modal.value = null; msg.value = 'Saved.'; await load()
    if (kind === 'assess') selected.value = assessForm.value.subject.trim()
  } catch (e) { err.value = String(e.message || e) }
}
function stkind(s) { return (s === 'signed' || s === 'approved' || s === 'done') ? 'ok' : s === 'open' ? 'warn' : 'muted' }
onMounted(load)
</script>
<template>
  <div class="grid gap-4">
    <div class="flex items-center gap-2 flex-wrap">
      <Badge kind="ver">{{ systems.length }} systems</Badge>
      <Badge kind="muted">{{ records.length }} records</Badge>
      <div class="ml-auto flex gap-2">
        <Btn size="sm" variant="ghost" @click="openRisk">New risk</Btn>
        <Btn size="sm" variant="ghost" @click="openCard">New model card</Btn>
        <Btn size="sm" @click="openAssess">New assessment</Btn>
      </div>
    </div>
    <p v-if="msg" class="text-ok text-sm">{{ msg }}</p>

    <div class="grid md:grid-cols-[280px_1fr] gap-4">
      <!-- AI-system registry (the hub) -->
      <Card title="AI systems" subtitle="registry">
        <div class="grid gap-1">
          <button v-for="s in systems" :key="s.name" @click="selected = s.name; tab='all'"
            class="text-left px-3 py-2 rounded-lg border transition"
            :class="selected===s.name ? 'border-accent bg-accent/10' : 'border-line hover:bg-panel2'">
            <div class="text-sm font-medium truncate">{{ s.name }}</div>
            <div class="text-xs text-dim">{{ Object.entries(s.kinds).map(([k,n]) => k+': '+n).join(' · ') }}</div>
          </button>
          <p v-if="!systems.length" class="text-dim text-sm py-6 text-center">No systems yet. Create an assessment to register one.</p>
        </div>
      </Card>

      <!-- System workspace -->
      <div class="grid gap-4">
        <Card v-if="current" :title="current.name" subtitle="system workspace">
          <template #cta><Btn size="sm" variant="ghost" @click="router.push('/reports')">Compliance report</Btn></template>
          <div class="flex gap-1 bg-panel2 border border-line rounded-lg p-1 w-fit mb-3">
            <button v-for="t in [['all','All'],['assessments','Assessments'],['risks','Risks'],['cards','Model cards']]" :key="t[0]"
              @click="tab=t[0]" class="px-3 py-1 rounded-md text-xs"
              :class="tab===t[0] ? 'bg-accent text-white' : 'text-dim hover:text-txt'">{{ t[1] }}</button>
          </div>
          <DataTable :columns="['Kind','Title','Status','ID']">
            <tr v-for="r in currentRecords" :key="r.id" class="border-b border-line/60">
              <td class="py-2 pr-4">{{ r.kind }}</td>
              <td class="py-2 pr-4">{{ r.title }}</td>
              <td class="py-2 pr-4"><Badge :kind="stkind(r.status)">{{ r.status }}</Badge></td>
              <td class="py-2 pr-4 font-mono text-xs">{{ r.id }}</td>
            </tr>
            <tr v-if="!currentRecords.length"><td colspan="4" class="py-6 text-center text-dim">No records in this tab.</td></tr>
          </DataTable>
        </Card>
        <Card v-else title="All governance records">
          <DataTable :columns="['System','Kind','Title','Status']">
            <tr v-for="r in records" :key="r.id" class="border-b border-line/60 cursor-pointer hover:bg-panel2/50" @click="selected = r.subject">
              <td class="py-2 pr-4">{{ r.subject }}</td>
              <td class="py-2 pr-4">{{ r.kind }}</td>
              <td class="py-2 pr-4 text-dim">{{ r.title }}</td>
              <td class="py-2 pr-4"><Badge :kind="stkind(r.status)">{{ r.status }}</Badge></td>
            </tr>
            <tr v-if="!records.length"><td colspan="4" class="py-6 text-center text-dim">No governance records yet.</td></tr>
          </DataTable>
        </Card>
      </div>
    </div>

    <!-- New assessment (framework-aware) -->
    <Modal v-if="modal==='assess'" title="New assessment" @close="modal=null">
      <div class="grid gap-3">
        <label class="text-xs text-dim">AI system<input v-model="assessForm.subject" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="system name" /></label>
        <label class="text-xs text-dim">Framework
          <select v-model="assessForm.framework" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option v-for="f in frameworks" :key="f.slug" :value="f.slug">{{ f.name }}</option>
          </select>
        </label>
        <div class="border border-line rounded-lg p-3 max-h-80 overflow-y-auto">
          <div class="text-xs text-dim mb-2">Conformity checklist &middot; {{ frameworkControls.length }} controls. Tick the controls already in place; the rest are recorded as open.</div>
          <label v-for="c in frameworkControls" :key="c.control_id" class="flex items-start gap-2 text-[13px] py-0.5">
            <input type="checkbox" v-model="checked[c.control_id]" class="mt-1" />
            <span><span class="font-mono text-xs text-dim mr-1">{{ c.reference || c.control_id }}</span>{{ c.title }}</span>
          </label>
          <p v-if="!frameworkControls.length" class="text-dim text-xs">No controls found for this framework.</p>
        </div>
        <div class="flex items-center gap-3"><Btn @click="submit('assess')">Create</Btn><span v-if="err" class="text-bad text-sm">{{ err }}</span></div>
      </div>
    </Modal>

    <!-- New risk -->
    <Modal v-if="modal==='risk'" title="New risk" @close="modal=null">
      <div class="grid gap-3">
        <label class="text-xs text-dim">AI system<input v-model="riskForm.subject" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <label class="text-xs text-dim">Title<input v-model="riskForm.title" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <div class="grid grid-cols-3 gap-2">
          <label class="text-xs text-dim">Likelihood
            <select v-model="riskForm.likelihood" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option>low</option><option>medium</option><option>high</option></select>
          </label>
          <label class="text-xs text-dim">Impact
            <select v-model="riskForm.impact" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option>low</option><option>medium</option><option>high</option></select>
          </label>
          <label class="text-xs text-dim">Treatment
            <select v-model="riskForm.treatment" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option>mitigate</option><option>accept</option><option>transfer</option><option>avoid</option></select>
          </label>
        </div>
        <label class="text-xs text-dim">Owner<input v-model="riskForm.owner" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="(you)" /></label>
        <div class="flex items-center gap-3"><Btn @click="submit('risk')">Create</Btn><span v-if="err" class="text-bad text-sm">{{ err }}</span></div>
      </div>
    </Modal>

    <!-- New model card -->
    <Modal v-if="modal==='modelcard'" title="New model card" @close="modal=null">
      <div class="grid gap-3">
        <label class="text-xs text-dim">AI system<input v-model="cardForm.subject" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <label class="text-xs text-dim">Title<input v-model="cardForm.title" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <div class="grid grid-cols-3 gap-2">
          <label class="text-xs text-dim">Model ID<input v-model="cardForm.model_id" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
          <label class="text-xs text-dim">Use-case ID<input v-model="cardForm.use_case_id" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
          <label class="text-xs text-dim">Risk ID<input v-model="cardForm.risk_id" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        </div>
        <label class="text-xs text-dim">Summary<textarea v-model="cardForm.summary" rows="3" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"></textarea></label>
        <div class="flex items-center gap-3"><Btn @click="submit('modelcard')">Create</Btn><span v-if="err" class="text-bad text-sm">{{ err }}</span></div>
      </div>
    </Modal>
  </div>
</template>
