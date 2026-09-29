<script setup>
import { ref } from 'vue'
import { getOr, post } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import Badge from '../components/ui/Badge.vue'
import Btn from '../components/ui/Btn.vue'
const err = ref(''); const reason = ref('')
const { data, refresh } = usePoll(() => getOr('/break-glass', {}))
const engaged = () => !!(data.value?.engaged || data.value?.active)
async function act(verb) {
  err.value = ''
  try { await post(`/break-glass/${verb}`, { reason: reason.value }, 'BreakGlassOperator'); await refresh() }
  catch (e) { err.value = String(e.message || e) }
}
</script>
<template>
  <Card title="Kill-switch / break-glass" subtitle="emergency stop">
    <div class="flex items-center gap-3 mb-4">
      <Badge :kind="engaged() ? 'bad' : 'ok'">{{ engaged() ? 'ENGAGED - agents halted' : 'normal operation' }}</Badge>
    </div>
    <div class="flex flex-wrap items-end gap-3">
      <label class="text-xs text-dim flex-1 min-w-56">Reason
        <input v-model="reason" class="mt-1 block w-full bg-panel2 border border-line rounded-md px-2 py-1.5 text-sm" placeholder="why" />
      </label>
      <Btn variant="bad" :disabled="engaged()" @click="act('engage')">Engage kill-switch</Btn>
      <Btn variant="ghost" :disabled="!engaged()" @click="act('clear')">Clear</Btn>
    </div>
    <p v-if="err" class="text-bad text-sm mt-3">{{ err }}</p>
  </Card>
</template>
