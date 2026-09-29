<script setup>
defineProps({ label: String, value: [String, Number], tone: String })
const tones = { ok: 'text-ok', bad: 'text-bad', warn: 'text-warn', accent: 'text-accent' }
</script>
<template>
  <div class="bg-panel2 border border-line rounded-xl px-4 py-3">
    <div class="text-2xl font-semibold" :class="tone ? tones[tone] : 'text-txt'">{{ value }}</div>
    <div class="text-xs text-dim mt-0.5 uppercase tracking-wide">{{ label }}</div>
  </div>
</template>
