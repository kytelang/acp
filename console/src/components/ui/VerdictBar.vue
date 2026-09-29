<script setup>
const props = defineProps({ verdicts: { type: Object, default: () => ({}) } })
const order = ['allow', 'step_up', 'shadow', 'deny']
const color = { allow: 'var(--ok)', step_up: 'var(--warn)', shadow: 'var(--accent)', deny: 'var(--bad)' }
function seg() {
  const total = Object.values(props.verdicts).reduce((a, b) => a + b, 0) || 1
  return order.filter(k => (props.verdicts[k] || 0) > 0)
    .map(k => ({ k, pct: ((props.verdicts[k] || 0) / total) * 100, n: props.verdicts[k] || 0 }))
}
</script>
<template>
  <div>
    <div class="flex h-3 rounded-full overflow-hidden border border-line">
      <div v-for="s in seg()" :key="s.k" :style="{ width: s.pct + '%', background: color[s.k] }" :title="`${s.k}: ${s.n}`" />
    </div>
    <div class="flex gap-4 mt-2 text-xs text-dim flex-wrap">
      <span v-for="k in order" :key="k" class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-sm inline-block" :style="{ background: color[k] }" />
        {{ k }} <b class="text-txt">{{ verdicts[k] || 0 }}</b>
      </span>
    </div>
  </div>
</template>
