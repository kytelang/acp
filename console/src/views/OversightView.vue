<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
const { data } = usePoll(async () => asList(await getOr('/oversight', { items: [] }), 'items', 'oversight', 'records'))
</script>
<template>
  <Card title="Oversight quality" subtitle="human-oversight signals (EU AI Act Art. 14)">
    <DataTable :columns="['Metric','Value']">
      <tr v-for="(row,i) in (data||[])" :key="i" class="border-b border-line/60">
        <td class="py-2 pr-4">{{ row.metric || row.key || row.name || '-' }}</td>
        <td class="py-2 pr-4">{{ row.value ?? row.count ?? '-' }}</td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="2" class="py-6 text-center text-dim">No oversight signals yet.</td></tr>
    </DataTable>
  </Card>
</template>
