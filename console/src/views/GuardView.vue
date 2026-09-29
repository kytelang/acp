<script setup>
import { ref, onMounted } from 'vue'
import { get, getOr } from '../api.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'

// Guard is configured per group (the agent-config `guard` capability). This screen consolidates the
// guarded tool servers across all groups: their listen/upstream and pinned key, and whether guard is on.
const rows = ref([])
const loading = ref(true)
onMounted(async () => {
  const g = await getOr('/groups', { groups: [] })
  const groups = g.groups || []
  const out = []
  for (const name of groups) {
    const cfg = await getOr(`/agent-config/${encodeURIComponent(name)}`, { config: {} })
    const guard = (cfg.config || {}).guard || {}
    out.push({ group: name, enabled: !!guard.enabled, listen: guard.listen || '', upstream: guard.upstream || '', pubkey: guard.pubkey || '' })
  }
  rows.value = out
  loading.value = false
})
</script>
<template>
  <div class="grid gap-4">
    <Card title="Guarded tool servers" subtitle="MCP/tool guard per directory group">
      <DataTable :columns="['Group','Guard','Listen','Upstream','Pinned key']">
        <tr v-for="r in rows" :key="r.group" class="border-b border-line/60">
          <td class="py-2 pr-4">{{ r.group }}</td>
          <td class="py-2 pr-4"><Badge :kind="r.enabled ? 'ok' : 'muted'">{{ r.enabled ? 'enforced' : 'off' }}</Badge></td>
          <td class="py-2 pr-4 font-mono text-xs">{{ r.listen || '-' }}</td>
          <td class="py-2 pr-4 font-mono text-xs truncate max-w-xs">{{ r.upstream || '-' }}</td>
          <td class="py-2 pr-4 font-mono text-xs truncate max-w-[10rem]">{{ r.pubkey ? (r.pubkey.slice(0,16) + '…') : '-' }}</td>
        </tr>
        <tr v-if="!loading && !rows.length"><td colspan="5" class="py-6 text-center text-dim">No groups configured. Register a group and enable guard in Agent config.</td></tr>
        <tr v-if="loading"><td colspan="5" class="py-6 text-center text-dim">Loading…</td></tr>
      </DataTable>
      <p class="text-xs text-dim mt-3">Guard rejects uninstrumented tool calls: only calls proxied through a guarded server (with a pinned key where set) are admitted. Configure per group under Agent config.</p>
    </Card>
  </div>
</template>
