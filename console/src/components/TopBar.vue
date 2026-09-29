<script setup>
import { ref } from 'vue'
import { Sun, Moon } from 'lucide-vue-next'
import { getTenant, setTenant } from '../api.js'
const dark = ref(!document.documentElement.classList.contains('light'))
function toggle() {
  dark.value = !dark.value
  document.documentElement.classList.toggle('light', !dark.value)
  localStorage.setItem('acp-theme', dark.value ? 'dark' : 'light')
}
const tenant = ref(getTenant())
function onTenant() { setTenant(tenant.value); location.reload() }
</script>
<template>
  <header class="app-topbar h-14 shrink-0 flex items-center gap-3 px-5 border-b border-line" :style="{ background: 'var(--topbar)' }">
    <div class="flex items-center gap-2 font-semibold tracking-tight">
      <span class="w-6 h-6 rounded-md bg-accent inline-flex items-center justify-center text-white text-xs">V</span>
      Varman
    </div>
    <span class="flex items-center gap-1.5 text-xs text-ok ml-1">
      <span class="w-2 h-2 rounded-full bg-ok animate-pulse" /> live
    </span>
    <div class="ml-auto flex items-center gap-3">
      <input v-model="tenant" @keyup.enter="onTenant" class="bg-panel2 border border-line rounded-md px-2 py-1 text-xs w-32"
             placeholder="tenant" title="x-acp-tenant" />
      <button @click="toggle" class="text-dim hover:text-txt" :title="dark ? 'Light theme' : 'Dark theme'">
        <component :is="dark ? Sun : Moon" :size="18" />
      </button>
    </div>
  </header>
</template>
