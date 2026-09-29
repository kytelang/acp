<script setup>
import { Pencil, Trash2 } from 'lucide-vue-next'
defineEmits(['edit', 'delete'])
</script>
<template>
  <div class="flex justify-end gap-1">
    <button class="text-dim hover:text-txt p-1 rounded" title="Edit" @click.stop="$emit('edit')"><Pencil :size="15" /></button>
    <button class="text-dim hover:text-bad p-1 rounded" title="Delete" @click.stop="$emit('delete')"><Trash2 :size="15" /></button>
  </div>
</template>
