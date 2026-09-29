<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
const { data } = usePoll(async () => asList(await getOr('/endpoints', { endpoints: [] }), 'endpoints'))
</script>
<template>
  <Card title="AI endpoints" subtitle="registered model API endpoints (LLM gateway)">
    <DataTable :columns="['ID','Name','URL','Class']">
      <tr v-for="e in (data||[])" :key="e.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ e.id }}</td>
        <td class="py-2 pr-4">{{ e.name || '-' }}</td>
        <td class="py-2 pr-4 font-mono text-xs truncate max-w-xs">{{ e.url || e.upstream || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ e.class || e.model_class || '-' }}</td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="4" class="py-6 text-center text-dim">No endpoints registered.</td></tr>
    </DataTable>
  </Card>
</template>
