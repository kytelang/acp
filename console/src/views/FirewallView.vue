<script setup>
import { ref, onMounted } from 'vue'
import { get, getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'

const cfg = ref({ enabled: false, block_secrets: false, block_toxicity: false, block_on_scanner_error: false, model: '', scan_url: '', deny_topics: [] })
const denyTopics = ref('')
const rules = ref([])
const rule = ref({ tool: '', app: '', agent: '', action: 'deny', classify: '' })
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
  const body = {}
  for (const k of ['tool', 'app', 'agent']) if (rule.value[k]) body[k] = rule.value[k]
  body.action = rule.value.action
  if (rule.value.classify) body.classify = rule.value.classify
  try { await post('/firewall/rules', body, 'FirewallAdmin'); rule.value = { tool: '', app: '', agent: '', action: 'deny', classify: '' }; await load() }
  catch (e) { err.value = String(e.message || e) }
}
async function del(id) {
  try { await post(`/firewall/rules/${id}/delete`, {}, 'FirewallAdmin'); await load() }
  catch (e) { err.value = String(e.message || e) }
}
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
          <td class="py-2 pr-4 font-mono text-xs">{{ [r.tool && ('tool='+r.tool), r.app && ('app='+r.app), r.agent && ('agent='+r.agent), r.port && ('port='+r.port)].filter(Boolean).join(' ') || '*' }}</td>
          <td class="py-2 pr-4"><Badge :kind="r.action==='deny' ? 'bad' : r.action==='allow' ? 'ok' : 'warn'">{{ r.action }}</Badge></td>
          <td class="py-2 pr-4 text-dim">{{ r.classify || '-' }}</td>
          <td class="py-2 pr-4"><Btn size="sm" variant="ghost" @click="del(r.id)">Delete</Btn></td>
        </tr>
        <tr v-if="!rules.length"><td colspan="5" class="py-6 text-center text-dim">No custom rules.</td></tr>
      </DataTable>
      <div class="grid sm:grid-cols-5 gap-2 mt-4 items-end">
        <label class="text-xs text-dim">Tool<input v-model="rule.tool" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="glob" /></label>
        <label class="text-xs text-dim">App<input v-model="rule.app" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <label class="text-xs text-dim">Agent<input v-model="rule.agent" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" /></label>
        <label class="text-xs text-dim">Action
          <select v-model="rule.action" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm">
            <option value="deny">deny</option><option value="allow">allow</option><option value="flag">flag</option>
          </select>
        </label>
        <Btn size="sm" @click="addRule">Add rule</Btn>
      </div>
    </Card>
  </div>
</template>
