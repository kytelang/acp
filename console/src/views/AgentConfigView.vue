<script setup>
import { ref, onMounted } from 'vue'
import { get, getOr, post } from '../api.js'
import Card from '../components/ui/Card.vue'
import Btn from '../components/ui/Btn.vue'
import Badge from '../components/ui/Badge.vue'

const groups = ref([])
const group = ref('')
const newGroup = ref('')
const cfg = ref(null)
const msg = ref(''); const err = ref('')

const blank = () => ({
  firewall: { enabled: true, listen: '127.0.0.1:8080' },
  mcp: { enabled: false, listen: '127.0.0.1:8090', upstream: '' },
  guard: { enabled: false, listen: '127.0.0.1:8091', upstream: '', pubkey: '' }
})

async function loadGroups() {
  const r = await getOr('/groups', { groups: [] })
  groups.value = r.groups || []
  if (!group.value && groups.value.length) group.value = groups.value[0]
}
async function loadConfig() {
  err.value = ''; msg.value = ''
  if (!group.value) { cfg.value = blank(); return }
  try {
    const r = await get(`/agent-config/${encodeURIComponent(group.value)}`)
    // The datastar console could not load stored config into the form; Vue two-way binding fixes that.
    cfg.value = { ...blank(), ...(r.config || {}) }
  } catch (e) { err.value = String(e.message || e); cfg.value = blank() }
}
async function register() {
  err.value = ''; msg.value = ''
  if (!newGroup.value.trim()) return
  try {
    await post('/groups', { name: newGroup.value.trim() }, 'PolicyAdmin')
    group.value = newGroup.value.trim(); newGroup.value = ''
    await loadGroups(); await loadConfig()
    msg.value = 'Group registered.'
  } catch (e) { err.value = String(e.message || e) }
}
async function save() {
  err.value = ''; msg.value = ''
  try { await post(`/agent-config/${encodeURIComponent(group.value)}`, { config: cfg.value }, 'PolicyAdmin'); msg.value = 'Saved.' }
  catch (e) { err.value = String(e.message || e) }
}
onMounted(async () => { await loadGroups(); await loadConfig() })
</script>
<template>
  <div class="grid gap-4">
    <Card title="Group" subtitle="config is keyed by IdP directory group">
      <div class="flex flex-wrap items-end gap-3">
        <label class="text-xs text-dim">Group
          <select v-model="group" @change="loadConfig" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm min-w-56">
            <option v-for="g in groups" :key="g" :value="g">{{ g }}</option>
            <option v-if="!groups.length" disabled value="">no groups registered</option>
          </select>
        </label>
        <div class="flex items-end gap-2">
          <label class="text-xs text-dim">Register new group
            <input v-model="newGroup" @keyup.enter="register" class="mt-1 block bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm w-48" placeholder="e.g. eng-agents" />
          </label>
          <Btn size="sm" variant="ghost" @click="register">Register</Btn>
        </div>
      </div>
    </Card>

    <Card v-if="cfg" title="Capabilities" :subtitle="group ? `agent-config for ${group}` : 'select a group'">
      <div class="grid gap-4">
        <div v-for="cap in ['firewall','mcp','guard']" :key="cap" class="border border-line rounded-lg p-3">
          <div class="flex items-center gap-2 mb-2">
            <label class="flex items-center gap-2 text-sm font-medium capitalize">
              <input type="checkbox" v-model="cfg[cap].enabled" /> {{ cap }}
            </label>
            <Badge :kind="cfg[cap].enabled ? 'ok' : 'muted'">{{ cfg[cap].enabled ? 'enabled' : 'off' }}</Badge>
          </div>
          <div class="grid sm:grid-cols-3 gap-2">
            <label class="text-xs text-dim">Listen
              <input v-model="cfg[cap].listen" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" />
            </label>
            <label v-if="cap!=='firewall'" class="text-xs text-dim">Upstream
              <input v-model="cfg[cap].upstream" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" />
            </label>
            <label v-if="cap==='guard'" class="text-xs text-dim">Pubkey
              <input v-model="cfg[cap].pubkey" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" />
            </label>
          </div>
        </div>
      </div>
      <div class="flex items-center gap-3 mt-4">
        <Btn @click="save" :disabled="!group">Save config</Btn>
        <span v-if="msg" class="text-ok text-sm">{{ msg }}</span>
        <span v-if="err" class="text-bad text-sm">{{ err }}</span>
      </div>
    </Card>
  </div>
</template>
