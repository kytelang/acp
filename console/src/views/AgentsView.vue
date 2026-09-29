<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
const { data } = usePoll(async () => asList(await getOr('/agents', { agents: [] }), 'agents'))
function tier(t) { return { high: 'bad', limited: 'warn', minimal: 'ok', unacceptable: 'bad' }[t] || 'muted' }
</script>
<template>
  <Card title="Agents" subtitle="registered agent identities">
    <DataTable :columns="['ID','Name','App','Risk tier','Status']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.id }}</td>
        <td class="py-2 pr-4">{{ a.name || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.app || a.app_id || '-' }}</td>
        <td class="py-2 pr-4"><Badge v-if="a.tier||a.risk_tier" :kind="tier(a.tier||a.risk_tier)">{{ a.tier || a.risk_tier }}</Badge><span v-else class="text-dim">-</span></td>
        <td class="py-2 pr-4"><Badge :kind="(a.status==='active'||a.active) ? 'ok' : 'muted'">{{ a.status || (a.active ? 'active' : '-') }}</Badge></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="5" class="py-6 text-center text-dim">No agents registered.</td></tr>
    </DataTable>
  </Card>
</template>
