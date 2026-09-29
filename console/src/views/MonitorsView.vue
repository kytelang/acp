<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
const { data } = usePoll(async () => {
  const [drift, lineage] = await Promise.all([getOr('/monitor/drift', {}), getOr('/monitor/lineage', {})])
  return { drift: asList(drift, 'drift', 'classes'), lineage: asList(lineage, 'lineage', 'sources') }
})
</script>
<template>
  <div class="grid gap-4">
    <Card title="Classifier drift" subtitle="content-firewall hit rates by class">
      <DataTable :columns="['Class','Hits','Total','Hit rate']">
        <tr v-for="(d,i) in (data?.drift||[])" :key="i" class="border-b border-line/60">
          <td class="py-2 pr-4">{{ d.class || d[0] }}</td>
          <td class="py-2 pr-4">{{ d.hits ?? d[1] }}</td>
          <td class="py-2 pr-4">{{ d.total ?? d[2] }}</td>
          <td class="py-2 pr-4">{{ (d.hit_rate ?? d.rate ?? d[3]) }}</td>
        </tr>
        <tr v-if="!(data?.drift||[]).length"><td colspan="4" class="py-6 text-center text-dim">No drift data.</td></tr>
      </DataTable>
    </Card>
    <Card title="Data lineage" subtitle="RAG / tool data sources">
      <DataTable :columns="['Source','Detail']">
        <tr v-for="(l,i) in (data?.lineage||[])" :key="i" class="border-b border-line/60">
          <td class="py-2 pr-4">{{ l.source || l.name || l }}</td>
          <td class="py-2 pr-4 text-dim text-xs">{{ l.detail || l.class || '' }}</td>
        </tr>
        <tr v-if="!(data?.lineage||[]).length"><td colspan="2" class="py-6 text-center text-dim">No lineage recorded.</td></tr>
      </DataTable>
    </Card>
  </div>
</template>
