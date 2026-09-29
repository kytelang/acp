<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
const { data, refresh } = usePoll(async () => asList(await getOr('/apps', { apps: [] }), 'apps'))
const showAdd = ref(false); const form = ref({ name: '', owner: '' }); const err = ref(''); const msg = ref('')
async function add() {
  err.value = ''
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  try {
    await post('/apps', { name: form.value.name.trim(), owner: form.value.owner }, 'AppRegistrar')
    form.value = { name: '', owner: '' }; showAdd.value = false; msg.value = 'Team registered.'; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
</script>
<template>
  <Card title="Teams / applications" subtitle="registered PEP identities">
    <template #cta><Btn size="sm" @click="showAdd = !showAdd">{{ showAdd ? 'Cancel' : 'New team' }}</Btn></template>
    <div v-if="showAdd" class="grid sm:grid-cols-[1fr_1fr_auto] gap-2 items-end mb-4 p-3 border border-line rounded-lg">
      <label class="text-xs text-dim">Name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. HR Portal" /></label>
      <label class="text-xs text-dim">Owner<input v-model="form.owner" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="team / owner" /></label>
      <Btn size="sm" @click="add">Register</Btn>
    </div>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="msg" class="text-ok text-sm mb-2">{{ msg }}</p>
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
