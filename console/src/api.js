// API client for acp-server. Same-origin in the embedded build (empty base). Sends the tenant header on
// every request and mints a dev-token per role for writes (a forwarded bearer wins if present).
const BASE = '' // same origin
let tenant = localStorage.getItem('acp-tenant') || 'default'
export function setTenant(t) { tenant = t; localStorage.setItem('acp-tenant', t) }
export function getTenant() { return tenant }

// Roles: AppRegistrar, PolicyAdmin, FirewallAdmin, GrcAuthor, Approver, Auditor, BreakGlassOperator.
const tokenCache = new Map()
let forwardedBearer = null
export function setBearer(b) { forwardedBearer = b }

async function tokenFor(role) {
  if (forwardedBearer) return forwardedBearer
  if (tokenCache.has(role)) return tokenCache.get(role)
  try {
    const r = await fetch(`${BASE}/auth/dev-token?role=${role}`, { headers: { 'x-acp-tenant': tenant } })
    if (!r.ok) return ''
    const j = await r.json()
    const t = j.token || ''
    if (t) tokenCache.set(role, t)
    return t
  } catch { return '' }
}

function headers(extra) { return { 'x-acp-tenant': tenant, ...(extra || {}) } }

export async function get(path) {
  const r = await fetch(`${BASE}${path}`, { headers: headers() })
  if (!r.ok) throw new Error(`${r.status} ${path}`)
  const ct = r.headers.get('content-type') || ''
  return ct.includes('json') ? r.json() : r.text()
}

// GET that never throws: returns a fallback on any error, for best-effort dashboard panels.
export async function getOr(path, fallback) {
  try { return await get(path) } catch { return fallback }
}

export async function post(path, body, role) {
  const token = await tokenFor(role)
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: headers({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }),
    body: JSON.stringify(body ?? {})
  })
  const ct = r.headers.get('content-type') || ''
  const data = ct.includes('json') ? await r.json() : await r.text()
  if (!r.ok) throw new Error(typeof data === 'string' ? data : (data.error || `${r.status}`))
  return data
}

// Authenticated download: fetch with a dev-token, then save the blob.
export async function download(path, role, filename) {
  const token = await tokenFor(role)
  const r = await fetch(`${BASE}${path}`, { headers: headers(token ? { authorization: `Bearer ${token}` } : {}) })
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}
