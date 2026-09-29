<script setup>
import { ref, onMounted } from 'vue'
import { getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const cfg = ref({ enabled: false, block_secrets: false, block_toxicity: false, block_on_scanner_error: false, model: '', scan_url: '', deny_topics: [] })
const denyTopics = ref('')
const rules = ref([])
// The content firewall is gateway/network scoped: rules match on host/path/sni/port, and the action is
// one of the firewall's own verbs (not allow/deny). These mirror the acp-server firewall handler.
const MATCH_KEYS = ['host_contains', 'host_suffix', 'host_exact', 'sni', 'path_contains', 'path_prefix']
const ACTIONS = ['inspect-prompt', 'govern-tool-call', 'dlp-only', 'block', 'pass']
const rule = ref({ matchKey: 'host_contains', matchVal: '', port: '', action: 'block', classify: '' })
const msg = ref(''); const err = ref('')

async function load() {
  const c = await getOr('/firewall/config', {})
  cfg.value = { ...cfg.value, ...c }
  denyTopics.value = (c.deny_topics || []).join(', ')
  const r = await getOr('/firewall/rules', { rules: [] })
  rules.value = Array.isArray(r) ? r : (r.rules || [])
}
async function saveConfig() {
  err.value = ''; msg.value = ''
  const body = { ...cfg.value, deny_topics: denyTopics.value.split(',').map(s => s.trim()).filter(Boolean) }
  try { await post('/firewall/config', body, 'FirewallAdmin'); msg.value = 'Config saved.'; await load() }
  catch (e) { err.value = String(e.message || e) }
}
async function addRule() {
  err.value = ''; msg.value = ''
  const body = { action: rule.value.action }
  if (rule.value.matchVal.trim()) body[rule.value.matchKey] = rule.value.matchVal.trim()
  if (rule.value.port) body.port = Number(rule.value.port)
  if (rule.value.classify) body.classify = rule.value.classify
  try { await post('/firewall/rules', body, 'FirewallAdmin'); rule.value = { matchKey: 'host_contains', matchVal: '', port: '', action: 'block', classify: '' }; await load() }
  catch (e) { err.value = String(e.message || e) }
}
async function del(id) {
  try { await post(`/firewall/rules/${id}/delete`, {}, 'FirewallAdmin'); await load() }
  catch (e) { err.value = String(e.message || e) }
}
function matchStr(m) {
  if (!m || typeof m !== 'object') return '*'
  return Object.entries(m).map(([k, v]) => `${k}=${v}`).join(' ') || '*'
}
function actKind(a) { return a === 'block' ? 'bad' : a === 'pass' ? 'ok' : 'warn' }
onMounted(load)
</script>
<template>
  <div class="grid gap-4">
    <Card title="Content firewall" subtitle="gateway-scope inspection">
      <div class="grid sm:grid-cols-2 gap-3">
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" v-model="cfg.enabled" /> Enabled</label>
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" v-model="cfg.block_secrets" /> Block secrets / PII</label>
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" v-model="cfg.block_toxicity" /> Block toxicity</label>
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" v-model="cfg.block_on_scanner_error" /> Fail closed on scanner error</label>
        <label class="text-xs text-dim">Classifier model
          <input v-model="cfg.model" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="(built-in)" />
        </label>
        <label class="text-xs text-dim">External scanner URL
          <input v-model="cfg.scan_url" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="(none)" />
        </label>
        <label class="text-xs text-dim sm:col-span-2">Deny topics (comma-separated)
          <input v-model="denyTopics" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" />
        </label>
      </div>
      <div class="flex items-center gap-3 mt-4">
        <Btn @click="saveConfig">Save config</Btn>
        <span v-if="msg" class="text-ok text-sm">{{ msg }}</span>
        <span v-if="err" class="text-bad text-sm">{{ err }}</span>
      </div>
    </Card>

    <Card title="Firewall rules" :subtitle="`${rules.length} rules`">
      <DataTable :columns="['ID','Match','Action','Classify','']">
        <tr v-for="r in rules" :key="r.id" class="border-b border-line/60">
          <td class="py-2 pr-4 font-mono text-xs">{{ r.id }}</td>
          <td class="py-2 pr-4 font-mono text-xs">{{ matchStr(r.match) }}</td>
          <td class="py-2 pr-4"><Badge :kind="actKind(r.action)">{{ r.action }}</Badge></td>
          <td class="py-2 pr-4 text-dim">{{ r.classify || '-' }}</td>
          <td class="py-2 pr-4"><Btn size="sm" variant="ghost" @click="del(r.id)">Delete</Btn></td>
        </tr>
        <tr v-if="!rules.length"><td colspan="5" class="py-6 text-center text-dim">No custom rules.</td></tr>
      </DataTable>
      <div class="grid sm:grid-cols-6 gap-2 mt-4 items-end">
        <label class="text-xs text-dim">Match on
          <select v-model="rule.matchKey" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option v-for="k in MATCH_KEYS" :key="k" :value="k">{{ k }}</option>
          </select>
        </label>
        <label class="text-xs text-dim sm:col-span-2">Value
          <input v-model="rule.matchVal" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. api.openai.com" />
        </label>
        <label class="text-xs text-dim">Port
          <input v-model="rule.port" type="number" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="(any)" />
        </label>
        <label class="text-xs text-dim">Action
          <select v-model="rule.action" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option v-for="a in ACTIONS" :key="a" :value="a">{{ a }}</option>
          </select>
        </label>
        <Btn size="sm" @click="addRule">Add rule</Btn>
      </div>
    </Card>
  </div>
</template>
