<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll, asList } from '../composables.js'
import Card from '../components/ui/Card.vue'
import DataTable from '../components/ui/DataTable.vue'
import Btn from '../components/ui/Btn.vue'
const { data, refresh } = usePoll(async () => asList(await getOr('/models', { models: [] }), 'models'))
const showAdd = ref(false); const form = ref({ name: '', provider: '', version: '', modality: 'text', description: '' }); const err = ref(''); const msg = ref('')
async function add() {
  err.value = ''
  if (!form.value.name.trim()) { err.value = 'Name is required.'; return }
  try {
    await post('/models', { name: form.value.name.trim(), provider: form.value.provider, version: form.value.version, card: { modality: form.value.modality, description: form.value.description.trim() } }, 'AppRegistrar')
    form.value = { name: '', provider: '', version: '', modality: 'text', description: '' }; showAdd.value = false; msg.value = 'Model registered.'; await refresh()
  } catch (e) { err.value = String(e.message || e) }
}
</script>
<template>
  <Card title="Models" subtitle="model registry">
    <template #cta><Btn size="sm" @click="showAdd = !showAdd">{{ showAdd ? 'Cancel' : 'New model' }}</Btn></template>
    <div v-if="showAdd" class="grid sm:grid-cols-2 gap-2 mb-4 p-3 border border-line rounded-lg">
      <label class="text-xs text-dim">Name<input v-model="form.name" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. gpt-4o" /></label>
      <label class="text-xs text-dim">Provider<input v-model="form.provider" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. OpenAI" /></label>
      <label class="text-xs text-dim">Version<input v-model="form.version" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="e.g. 2024-08" /></label>
      <label class="text-xs text-dim">Modality
        <select v-model="form.modality" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm"><option value="text">text</option><option value="vision">vision</option><option value="multimodal">multimodal</option><option value="embedding">embedding</option><option value="audio">audio</option></select>
      </label>
      <label class="text-xs text-dim sm:col-span-2">Description<input v-model="form.description" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="notes / model card summary" /></label>
      <div class="sm:col-span-2"><Btn size="sm" @click="add">Register</Btn></div>
    </div>
    <p v-if="err" class="text-bad text-sm mb-2">{{ err }}</p>
    <p v-if="msg" class="text-ok text-sm mb-2">{{ msg }}</p>
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
