<template>
  <XdpStatistics :statistics="statistics" :running="running" :interface-name="status?.interface" :error="error || status?.statistics_error" graph />
</template>

<script setup lang="ts">
import type { XdpStatistics } from '~/utils/xdpStatistics'

type Status = {
  service: { ActiveState?: string }
  interface: string
  statistics?: XdpStatistics | null
  statistics_error?: string
}
const { apiFetch, apiUrl } = useApi()
const status = ref<Status | null>(null)
const error = ref('')
const running = computed(() => status.value?.service.ActiveState === 'active')
const statistics = computed(() => {
  const sample = status.value?.statistics
  // Keep the last totals when the controller is unreachable, but never present
  // their rates as live traffic.
  return sample && error.value ? { ...sample, stale: true } : sample || null
})
let timer: ReturnType<typeof setTimeout> | undefined
let disposed = false
async function refresh() {
  try {
    const result = await apiFetch<Status>(apiUrl('/settings/xdp/status'), { timeout: 15000 })
    if (disposed) return
    status.value = result
    error.value = ''
  } catch (e: any) {
    if (disposed) return
    error.value = (e?.statusCode || e?.status) === 403
      ? 'Статистика XDP доступна администратору.'
      : 'Статистика XDP недоступна. Проверьте службу fess-xdp в настройках. Повторяем подключение автоматически.'
  } finally {
    if (!disposed) timer = setTimeout(refresh, 5000)
  }
}
onMounted(refresh)
onBeforeUnmount(() => { disposed = true; if (timer) clearTimeout(timer) })
</script>
