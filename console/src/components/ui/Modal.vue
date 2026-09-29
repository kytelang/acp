<script setup>
defineProps({ title: String, wide: Boolean })
const emit = defineEmits(['close'])
</script>
<template>
  <Teleport to="body">
    <div class="fixed inset-0 z-50 flex items-start justify-center bg-black/50 p-6 overflow-y-auto" @click.self="emit('close')">
      <div class="bg-panel border border-line2 rounded-xl w-full mt-12 shadow-2xl" :class="wide ? 'max-w-3xl' : 'max-w-lg'">
        <header class="flex items-center px-4 py-3 border-b border-line">
          <h3 class="text-sm font-semibold">{{ title }}</h3>
          <button class="ml-auto text-dim hover:text-txt text-lg leading-none" @click="emit('close')">&times;</button>
        </header>
        <div class="p-4"><slot /></div>
      </div>
    </div>
  </Teleport>
</template>
