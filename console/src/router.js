import { createRouter, createWebHashHistory } from 'vue-router'

// One route per view. Views are lazy-loaded so the initial bundle stays small.
const routes = [
  { path: '/', redirect: '/overview' },
  { path: '/overview', component: () => import('./views/OverviewView.vue'), meta: { title: 'Overview' } },
  { path: '/approvals', component: () => import('./views/ApprovalsView.vue'), meta: { title: 'Approvals' } },
  { path: '/oversight', component: () => import('./views/OversightView.vue'), meta: { title: 'Oversight' } },
  { path: '/evidence', component: () => import('./views/EvidenceView.vue'), meta: { title: 'Evidence' } },
  { path: '/violations', component: () => import('./views/ViolationsView.vue'), meta: { title: 'Violations' } },
  { path: '/reports', component: () => import('./views/ReportsView.vue'), meta: { title: 'Reports' } },
  { path: '/teams', component: () => import('./views/TeamsView.vue'), meta: { title: 'Teams' } },
  { path: '/agents', component: () => import('./views/AgentsView.vue'), meta: { title: 'Agents' } },
  { path: '/models', component: () => import('./views/ModelsView.vue'), meta: { title: 'Models' } },
  { path: '/endpoints', component: () => import('./views/EndpointsView.vue'), meta: { title: 'AI Endpoints' } },
  { path: '/policy', component: () => import('./views/PolicyView.vue'), meta: { title: 'Policy' } },
  { path: '/firewall', component: () => import('./views/FirewallView.vue'), meta: { title: 'Content firewall' } },
  { path: '/agent-config', component: () => import('./views/AgentConfigView.vue'), meta: { title: 'Agent config' } },
  { path: '/guard', component: () => import('./views/GuardView.vue'), meta: { title: 'Guard' } },
  { path: '/governance', component: () => import('./views/GovernanceView.vue'), meta: { title: 'Governance' } },
  { path: '/kill-switch', component: () => import('./views/KillSwitchView.vue'), meta: { title: 'Kill-switch' } },
  { path: '/integrity', component: () => import('./views/IntegrityView.vue'), meta: { title: 'Integrity' } },
  { path: '/monitors', component: () => import('./views/MonitorsView.vue'), meta: { title: 'Monitors' } }
]

// Hash history: client routes live under /#/... so they never collide with acp-server's top-level
// JSON API routes (e.g. GET /agents, /models, /oversight). The server only ever serves / (index),
// the flat assets, and the API. No route-shadowing, no server changes needed.
export const router = createRouter({ history: createWebHashHistory(), routes })
