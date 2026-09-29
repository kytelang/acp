<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import Sidebar from './components/Sidebar.vue'
import TopBar from './components/TopBar.vue'
const route = useRoute()
const title = computed(() => route.meta.title || 'Varman')
</script>
<template>
  <div class="h-full flex flex-col">
    <TopBar />
    <div class="flex-1 flex min-h-0">
      <Sidebar />
      <main class="app-content flex-1 overflow-y-auto">
        <div class="max-w-content mx-auto px-6 py-6">
          <h1 class="text-lg font-semibold mb-4">{{ title }}</h1>
          <RouterView />
        </div>
      </main>
    </div>
  </div>
</template>
