<script setup>
import { RouterLink } from 'vue-router'
import {
  LayoutDashboard, Hand, Eye, ScrollText, AlertTriangle, ClipboardList,
  Package, Bot, Brain, Globe, Lock, Shield, Laptop, FileText, OctagonAlert,
  ShieldCheck, LineChart, Waypoints, Boxes, Library
} from 'lucide-vue-next'

const groups = [
  { label: 'Governance', items: [
    { to: '/overview', text: 'Overview', icon: LayoutDashboard },
    { to: '/approvals', text: 'Approvals', icon: Hand },
    { to: '/oversight', text: 'Oversight', icon: Eye },
    { to: '/evidence', text: 'Evidence', icon: ScrollText },
    { to: '/violations', text: 'Violations', icon: AlertTriangle },
    { to: '/reports', text: 'Reports', icon: ClipboardList }
  ]},
  { label: 'Identity', items: [
    { to: '/teams', text: 'Teams', icon: Package },
    { to: '/agents', text: 'Agents', icon: Bot },
    { to: '/models', text: 'Models', icon: Brain },
    { to: '/endpoints', text: 'AI Endpoints', icon: Globe }
  ]},
  { label: 'Policy', items: [
    { to: '/policy', text: 'Policy', icon: Lock },
    { to: '/firewall', text: 'Content firewall', icon: Shield },
    { to: '/agent-config', text: 'Agent config', icon: Laptop },
    { to: '/guard', text: 'Guard', icon: Waypoints }
  ]},
  { label: 'Compliance', items: [
    { to: '/systems', text: 'AI systems', icon: Boxes },
    { to: '/packs', text: 'Policy packs', icon: Library },
    { to: '/governance', text: 'Governance', icon: FileText }
  ]},
  { label: 'Emergency', items: [
    { to: '/kill-switch', text: 'Kill-switch', icon: OctagonAlert }
  ]},
  { label: 'Health', items: [
    { to: '/integrity', text: 'Integrity', icon: ShieldCheck },
    { to: '/monitors', text: 'Monitors', icon: LineChart }
  ]}
]
</script>
<template>
  <aside class="app-sidebar w-[236px] shrink-0 border-r border-line overflow-y-auto" :style="{ background: 'var(--sidebar)' }">
    <nav class="py-3">
      <div v-for="g in groups" :key="g.label" class="mb-4">
        <div class="px-4 pb-1.5 text-[10px] uppercase tracking-widest text-muted font-semibold">{{ g.label }}</div>
        <RouterLink v-for="it in g.items" :key="it.to" :to="it.to" custom v-slot="{ href, isActive, navigate }">
          <a :href="href" @click="navigate"
             class="flex items-center gap-2.5 px-4 py-2 text-[13px] border-l-2 transition cursor-pointer"
             :class="isActive ? 'border-accent bg-accent/10 text-txt' : 'border-transparent text-dim hover:text-txt hover:bg-panel2/60'">
            <component :is="it.icon" :size="16" />
            {{ it.text }}
          </a>
        </RouterLink>
      </div>
    </nav>
  </aside>
</template>
