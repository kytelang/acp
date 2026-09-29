<script setup>
import { getOr } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
const { data } = usePoll(async () => asList(await getOr('/apps', { apps: [] }), 'apps'))
</script>
<template>
  <Card title="Teams / applications" subtitle="registered PEP identities">
    <DataTable :columns="['ID','Name','Owner','Status']">
      <tr v-for="a in (data||[])" :key="a.id" class="border-b border-line/60">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.id }}</td>
        <td class="py-2 pr-4">{{ a.name || a.title || '-' }}</td>
        <td class="py-2 pr-4 text-dim">{{ a.owner || a.team || '-' }}</td>
        <td class="py-2 pr-4"><Badge :kind="(a.status==='active'||a.active) ? 'ok' : 'muted'">{{ a.status || (a.active ? 'active' : '-') }}</Badge></td>
      </tr>
      <tr v-if="!(data||[]).length"><td colspan="4" class="py-6 text-center text-dim">No applications registered.</td></tr>
    </DataTable>
  </Card>
</template>
