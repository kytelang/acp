<script setup>
defineProps({ kind: { type: String, default: 'muted' } })
const map = {
  ok: 'text-ok border-ok/40 bg-ok/10',
  bad: 'text-bad border-bad/40 bg-bad/10',
  warn: 'text-warn border-warn/40 bg-warn/10',
  ver: 'text-accent border-accent/40 bg-accent/10',
  muted: 'text-dim border-line2 bg-panel2'
}
</script>
<template>
  <span class="inline-flex items-center px-2 py-0.5 rounded-full border text-[11px] font-medium" :class="map[kind] || map.muted"><slot /></span>
</template>
