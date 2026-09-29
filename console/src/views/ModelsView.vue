<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
const { data } = usePoll(async () => asList(await getOr('/models', { models: [] }), 'models'))
</script>
<template>
  <Card title="Models" subtitle="model registry">
    <DataTable :columns="['ID','Name','Provider','Version']">
      <tr v-for="m in (data||[])" :key="m.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ m.id }}</td>
        <td class="py-2 pr-4">{{ m.name || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ m.provider || m.vendor || '-' }}</td>
        <td class="py-2 pr-4">{{ m.version || '-' }}</td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="4" class="py-6 text-center text-dim">No models registered.</td></tr>
    </DataTable>
  </Card>
</template>
