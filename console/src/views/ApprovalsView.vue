<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Btn from '../components/ui/Btn.vue'
const err = ref('')
const { data, refresh } = usePoll(async () => {
  const r = await getOr('/approvals/pending', { pending: [] })
  return Array.isArray(r) ? r : (r.pending || r.holds || [])
})
async function act(id, verb) {
  err.value = ''
  try { await post(`/approvals/${id}/${verb}`, {}, 'Approver'); await refresh() }
  catch (e) { err.value = String(e.message || e) }
}
</script>
<template>
  <Card title="Pending approvals" subtitle="human-in-the-loop step-ups">
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <DataTable :columns="['ID','Agent','Tool','Reason','Actions']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.id }}</td>
        <td class="py-2 pr-4">{{ a.agent || a.principal || '-' }}</td>
        <td class="py-2 pr-4 font-mono text-xs">{{ a.tool || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.reason || '-' }}</td>
        <td class="py-2 pr-4 flex gap-2">
          <Btn size="sm" variant="ok" @click="act(a.id,'approve')">Approve</Btn>
          <Btn size="sm" variant="bad" @click="act(a.id,'deny')">Deny</Btn>
        </td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="5" class="py-6 text-center text-dim">No approvals awaiting a decision.</td></tr>
    </DataTable>
  </Card>
</template>
