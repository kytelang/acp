<script setup>
import { ref, onMounted } from 'vue'
import { get, getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const tab = ref('rules')
const current = ref({})
const rules = ref([])
const yaml = ref('version: 1\nenforcement_mode: enforce\ndefault: deny\nrules: []\n')
const authorText = ref('')
const authorResult = ref(null)
const msg = ref(''); const err = ref('')

async function load() {
  current.value = await getOr('/policy-store', {})
  const r = await getOr('/policy-store/rules', { rules: [] })
  rules.value = r.rules || []
}
async function deploy() {
  err.value = ''; msg.value = ''
  try { const r = await post('/policy-store/deploy', { policy: yaml.value }, 'PolicyAdmin'); msg.value = 'Deployed. ' + (r.hash ? ('hash ' + String(r.hash).slice(0, 12)) : ''); await load() }
  catch (e) { err.value = String(e.message || e) }
}
async function author() {
  err.value = ''; authorResult.value = null
  try { authorResult.value = await post('/policy/author', { text: authorText.value }, 'PolicyAdmin'); if (authorResult.value?.policy) yaml.value = authorResult.value.policy }
  catch (e) { err.value = String(e.message || e) }
}
function vkind(v) { return v === 'deny' ? 'bad' : v === 'allow' ? 'ok' : v === 'step_up' ? 'warn' : 'ver' }
onMounted(load)
</script>
<template>
  <div class="grid gap-4">
    <div class="flex gap-1 bg-panel2 border border-line rounded-lg p-1 w-fit">
      <button v-for="t in [['rules','Deployed rules'],['author','Author'],['deploy','Deploy YAML']]" :key="t[0]"
        @click="tab=t[0]" class="px-3 py-1.5 rounded-md text-[13px]"
        :class="tab===t[0] ? 'bg-accent text-white' : 'text-dim hover:text-txt'">{{ t[1] }}</button>
    </div>

    <Card v-if="tab==='rules'" title="Enforced policy" :subtitle="`version ${current.version ?? 0}${current.enforcement_mode ? ' · ' + current.enforcement_mode : ''}`">
      <DataTable :columns="['ID','Subject','Operation','Verdict','Reason']">
        <tr v-for="r in rules" :key="r.id" class="border-b border-line/60">
          <td class="py-2 pr-4 font-mono text-xs">{{ r.id }}</td>
          <td class="py-2 pr-4 font-mono text-xs">{{ r.subject || r.app || r.agent || r.group || '*' }}</td>
          <td class="py-2 pr-4">{{ r.operation || r.tool || '*' }}</td>
          <td class="py-2 pr-4"><Badge :kind="vkind(r.verdict)">{{ r.verdict }}</Badge></td>
          <td class="py-2 pr-4 text-dim text-xs">{{ r.reason || '' }}</td>
        </tr>
        <tr v-if="!rules.length"><td colspan="5" class="py-6 text-center text-dim">No rules deployed.</td></tr>
      </DataTable>
    </Card>

    <Card v-if="tab==='author'" title="Author from description" subtitle="natural-language to policy">
      <textarea v-model="authorText" rows="4" class="w-full bg-panel2 border border-line rounded-md px-3 py-2 text-sm font-mono"
        placeholder="e.g. deny payments over 5000 for the finance group unless a human approves"></textarea>
      <div class="flex items-center gap-3 mt-3"><Btn @click="author">Generate</Btn><span v-if="err" class="text-bad text-sm">{{ err }}</span></div>
      <pre v-if="authorResult" class="mt-3 text-xs text-dim overflow-x-auto bg-panel2 border border-line rounded-md p-3">{{ JSON.stringify(authorResult, null, 2) }}</pre>
    </Card>

    <Card v-if="tab==='deploy'" title="Deploy policy" subtitle="signed deploy (PolicyAdmin)">
      <textarea v-model="yaml" rows="14" class="w-full bg-panel2 border border-line rounded-md px-3 py-2 text-xs font-mono"></textarea>
      <div class="flex items-center gap-3 mt-3">
        <Btn @click="deploy">Deploy</Btn>
        <span v-if="msg" class="text-ok text-sm">{{ msg }}</span>
        <span v-if="err" class="text-bad text-sm">{{ err }}</span>
      </div>
    </Card>
  </div>
</template>
