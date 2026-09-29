import { ref, onMounted, onUnmounted } from 'vue'

// Poll an async loader on an interval (default 2s), with a `data`/`loading` ref pair. Stops on unmount.
export function usePoll(loader, intervalMs = 2000) {
  const data = ref(null)
  const loading = ref(true)
  let timer = null
  async function tick() {
    try { data.value = await loader() } catch { /* keep last good value */ }
    loading.value = false
  }
  onMounted(() => { tick(); timer = setInterval(tick, intervalMs) })
  onUnmounted(() => { if (timer) clearInterval(timer) })
  return { data, loading, refresh: tick }
}

// Normalise an API response that may be a bare array or an object wrapping one under a known key.
export function asList(x, ...keys) {
  if (Array.isArray(x)) return x
  if (x && typeof x === 'object') {
    for (const k of keys) if (Array.isArray(x[k])) return x[k]
    for (const v of Object.values(x)) if (Array.isArray(v)) return v
  }
  return []
}
