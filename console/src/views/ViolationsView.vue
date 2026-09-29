<script setup>
import { getOr, download } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
const { data } = usePoll(() => getOr('/report/violations', { total: 0, recent: [], by_rule: [], by_agent: [] }))
function ts(ms) { return ms ? new Date(ms).toLocaleString() : '-' }
function vkind(v) { return v === 'deny' ? 'bad' : v === 'step_up' ? 'warn' : v === 'block' ? 'bad' : 'muted' }
</script>
<template>
  <div class="grid gap-4">
    <Card title="Recent violations" :subtitle="`${data?.total ?? 0} total`">
      <template #cta><Btn size="sm" variant="ghost" @click="download('/report/violations.csv','Auditor','violations.csv')">Export CSV</Btn></template>
      <DataTable :columns="['When','Agent','Tool','Verdict','Rule','Impact','Outcome']">
        <tr v-for="(r,i) in (data?.recent||[])" :key="i" class="border-b border-line/60">
          <td class="py-2 pr-4 whitespace-nowrap text-dim">{{ ts(r.ts_ms) }}</td>
          <td class="py-2 pr-4">{{ r.agent || '-' }}</td>
          <td class="py-2 pr-4 font-mono text-xs">{{ r.tool || '-' }}</td>
          <td class="py-2 pr-4"><Badge :kind="vkind(r.verdict)">{{ r.verdict || '-' }}</Badge></td>
          <td class="py-2 pr-4">{{ r.rule_id || '-' }}</td>
          <td class="py-2 pr-4">{{ r.impact || '-' }}</td>
          <td class="py-2 pr-4">{{ r.outcome || '-' }}</td>
        </tr>
        <tr v-if="!(data?.recent||[]).length"><td colspan="7" class="py-6 text-center text-dim">No violations recorded.</td></tr>
      </DataTable>
    </Card>
  </div>
</template>
