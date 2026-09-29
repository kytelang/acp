<script setup>
import { getOr } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
const { data } = usePoll(async () => {
  const [recent, events] = await Promise.all([getOr('/evidence/recent', []), getOr('/events/recent', [])])
  const norm = x => Array.isArray(x) ? x : (x.records || x.events || x.recent || [])
  return { recent: norm(recent), events: norm(events) }
})
function ts(ms) { return ms ? new Date(ms).toLocaleString() : '-' }
</script>
<template>
  <div class="grid gap-4">
    <Card title="Recent evidence" subtitle="tamper-evident ledger">
      <DataTable :columns="['When','Type','Detail']">
        <tr v-for="(r,i) in (data?.recent||[])" :key="i" class="border-b border-line/60">
          <td class="py-2 pr-4 text-dim whitespace-nowrap">{{ ts(r.ts_ms || r.created_ms) }}</td>
          <td class="py-2 pr-4">{{ r.type || r.kind || '-' }}</td>
          <td class="py-2 pr-4 font-mono text-xs truncate max-w-md">{{ r.tool || r.subject || r.id || JSON.stringify(r).slice(0,80) }}</td>
        </tr>
        <tr v-if="!(data?.recent||[]).length"><td colspan="3" class="py-6 text-center text-dim">No evidence yet.</td></tr>
      </DataTable>
    </Card>
  </div>
</template>
