<template>
  <XdpStatistics :statistics="statistics" :running="running" :interface-name="status?.interface" :error="error || status?.statistics_error" :history="history" :history-error="historyError" :history-loading="historyLoading" :period="period" @period-change="changePeriod" graph />
</template>

<script setup lang="ts">
import type { XdpStatistics, XdpHistory, XdpPeriod } from '~/utils/xdpStatistics'

type Status = {
  service: { ActiveState?: string }
  interface: string
  statistics?: XdpStatistics | null
  statistics_error?: string
}
const { apiFetch, apiUrl } = useApi()
const status = ref<Status | null>(null)
const error = ref('')
const history = shallowRef<XdpHistory | null>(null)
const historyError = ref('')
const historyLoading = ref(false)
const period = ref<XdpPeriod>('hour')
let historyTimer: ReturnType<typeof setTimeout> | undefined
let historyGeneration = 0
async function refreshHistory() {
  const generation = ++historyGeneration
  if (historyTimer) clearTimeout(historyTimer)
  historyLoading.value = true
  try {
    const result = await apiFetch<XdpHistory>(apiUrl(`/dashboard/xdp/history?period=${period.value}`), { timeout: 10000 })
    if (disposed || generation !== historyGeneration) return
    history.value = result
    historyError.value = ''
  } catch {
    if (disposed || generation !== historyGeneration) return
    historyError.value = history.value ? 'Не удалось обновить историю XDP. Показаны последние полученные данные.' : 'История XDP недоступна. Повторяем подключение автоматически.'
  } finally {
    if (!disposed && generation === historyGeneration) {
      historyLoading.value = false
      historyTimer = setTimeout(refreshHistory, 10000)
    }
  }
}
function changePeriod(value: XdpPeriod) {
  if (period.value === value) return
  period.value = value
  history.value = null
  historyError.value = ''
  try { localStorage.setItem('fess-xdp-history-period', value) } catch {}
  refreshHistory()
}
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
onMounted(() => {
  try {
    const saved = localStorage.getItem('fess-xdp-history-period')
    if (saved === 'hour' || saved === 'day' || saved === 'week') period.value = saved
  } catch {}
  refresh()
  refreshHistory()
})
onBeforeUnmount(() => { disposed = true; ++historyGeneration; if (historyTimer) clearTimeout(historyTimer); if (timer) clearTimeout(timer) })
</script>
