<script setup>
defineProps({ variant: { type: String, default: 'primary' }, size: String, disabled: Boolean })
const map = {
  primary: 'bg-accent text-white hover:opacity-90',
  ok: 'bg-ok text-white hover:opacity-90',
  bad: 'bg-bad text-white hover:opacity-90',
  ghost: 'border border-line2 text-txt hover:bg-panel2'
}
</script>
<template>
  <button :disabled="disabled"
    class="inline-flex items-center gap-1.5 rounded-lg font-medium transition disabled:opacity-50 disabled:cursor-not-allowed"
    :class="[map[variant] || map.primary, size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3.5 py-2 text-[13px]']">
    <slot />
  </button>
</template>
