<script setup>
import { getOr } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import Badge from '../components/ui/Badge.vue'
const { data } = usePoll(async () => {
  const [verify, trust] = await Promise.all([getOr('/verify', {}), getOr('/trust', {})])
  return { verify, trust }
})
</script>
<template>
  <div class="grid gap-4">
    <Card title="Ledger integrity" subtitle="/verify">
      <div class="flex items-center gap-2">
        <Badge :kind="data?.verify?.ok || data?.verify?.verified ? 'ok' : 'bad'">
          {{ (data?.verify?.ok || data?.verify?.verified) ? 'verified' : 'unverified' }}
        </Badge>
        <span class="text-dim text-sm">{{ data?.verify?.records ? (data.verify.records + ' records') : '' }}</span>
      </div>
      <pre class="mt-3 text-xs text-dim overflow-x-auto">{{ JSON.stringify(data?.verify || {}, null, 2) }}</pre>
    </Card>
    <Card title="Trust posture" subtitle="/trust">
      <pre class="text-xs text-dim overflow-x-auto">{{ JSON.stringify(data?.trust || {}, null, 2) }}</pre>
    </Card>
  </div>
</template>
