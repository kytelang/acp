<script setup>
import { computed } from 'vue'
import { getOr } from '../api.js'
import { usePoll } from '../composables.js'
import Card from '../components/ui/Card.vue'
import StatTile from '../components/ui/StatTile.vue'
import VerdictBar from '../components/ui/VerdictBar.vue'
import Badge from '../components/ui/Badge.vue'

const { data } = usePoll(async () => {
  const [report, viol, approvals, live] = await Promise.all([
    getOr('/report', {}),
    getOr('/report/violations', { total: 0 }),
    getOr('/approvals/pending', { pending: [] }),
    getOr('/liveness', {})
  ])
  const pend = Array.isArray(approvals) ? approvals : (approvals.pending || approvals.holds || [])
  return { report, viol, pending: pend.length, live }
})

const verdicts = computed(() => data.value?.report?.verdicts || {})
const coveragePct = computed(() => Math.round((data.value?.report?.policy_coverage || 0) * 100))
</script>
<template>
  <div class="grid gap-4">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <StatTile label="Evidence records" :value="data?.report?.records ?? '-'" />
      <StatTile label="Decisions" :value="data?.report?.decisions ?? '-'" tone="accent" />
      <StatTile label="Violations" :value="data?.viol?.total ?? '-'" :tone="(data?.viol?.total||0) > 0 ? 'bad' : 'ok'" />
      <StatTile label="Approvals pending" :value="data?.pending ?? '-'" :tone="(data?.pending||0) > 0 ? 'warn' : 'ok'" />
    </div>

    <Card title="Decision posture" subtitle="live, refreshed every 2s">
      <VerdictBar :verdicts="verdicts" />
      <div class="mt-4 flex items-center gap-2 text-sm">
        <span class="text-dim">Policy coverage</span>
        <div class="flex-1 h-2 bg-panel2 rounded-full overflow-hidden max-w-xs">
          <div class="h-full bg-accent" :style="{ width: coveragePct + '%' }" />
        </div>
        <b>{{ coveragePct }}%</b>
      </div>
    </Card>

    <Card title="Control plane">
      <div class="flex flex-wrap gap-2 text-sm">
        <Badge kind="ok">server online</Badge>
        <Badge :kind="(data?.viol?.total||0) > 0 ? 'bad' : 'ok'">
          {{ (data?.viol?.total||0) > 0 ? (data.viol.total + ' violations') : 'no violations' }}
        </Badge>
        <Badge :kind="(data?.pending||0) > 0 ? 'warn' : 'ok'">
          {{ (data?.pending||0) > 0 ? (data.pending + ' awaiting approval') : 'no pending approvals' }}
        </Badge>
        <Badge kind="ver">tenant scoped</Badge>
      </div>
    </Card>
  </div>
</template>
