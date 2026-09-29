<script setup>
defineProps({ title: String, subtitle: String })
</script>
<template>
  <section class="bg-panel border border-line rounded-xl overflow-hidden">
    <header v-if="title || $slots.cta || subtitle" class="flex items-center gap-3 px-4 py-3 border-b border-line">
      <h2 class="text-[13px] font-semibold tracking-wide">{{ title }}</h2>
      <span v-if="subtitle" class="text-xs text-dim ml-auto">{{ subtitle }}</span>
      <div v-if="$slots.cta" :class="subtitle ? '' : 'ml-auto'"><slot name="cta" /></div>
    </header>
    <div class="p-4 overflow-x-auto"><slot /></div>
  </section>
</template>
