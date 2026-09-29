<script setup>
defineProps({ columns: { type: Array, default: () => [] } })
</script>
<template>
  <table class="w-full border-collapse text-[13px]">
    <thead>
      <tr class="text-left">
        <th v-for="c in columns" :key="c"
            class="text-[11px] uppercase tracking-wide text-muted font-semibold pb-2 border-b border-line pr-4 whitespace-nowrap">{{ c }}</th>
      </tr>
    </thead>
    <tbody><slot /></tbody>
  </table>
</template>
