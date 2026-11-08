<template>
  <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
    <h4 class="text-sm font-semibold">Оповещения XDP</h4>
    <p class="mt-1 text-xs text-slate-400">Состояние сейчас, независимо от выбранного периода графика.</p>
    <p v-if="error" role="alert" class="mt-2 text-xs text-amber-300">{{ error }}</p>
    <p v-if="alerts === null && !error" class="mt-2 text-xs text-slate-400">Загрузка…</p>
    <template v-if="alerts !== null">
      <p v-if="!active.length" class="mt-2 text-sm text-slate-400">{{ error ? 'При последней проверке активных оповещений не было.' : 'Активных оповещений нет.' }}</p>
      <div v-for="item in active" :key="item.kind" role="alert" class="mt-2 rounded-lg bg-amber-950/50 p-3 text-sm text-amber-200">
        <strong>{{ title(item) }}</strong> · с {{ date(item.opened_ms) }}
        <p v-if="item.kind === 'drop_share'" class="mt-1">{{ evidence(item) }}</p>
      </div>
      <details v-if="closed.length" class="mt-3 text-xs text-slate-400">
        <summary class="cursor-pointer">Завершённые оповещения ({{ closed.length }})</summary>
        <p v-for="item in closed" :key="item.kind + item.opened_ms" class="mt-2">
          {{ date(item.opened_ms) }} — {{ date(item.closed_ms!) }} · {{ title(item) }}
          <span v-if="item.kind === 'drop_share'"> · {{ evidence(item) }}</span>
        </p>
      </details>
    </template>
  </section>
</template>

<script setup lang="ts">
import { xdpDropReasons } from '~/utils/xdpStatistics'
type Alert = { kind: 'drop_share' | 'collection_gap'; opened_ms: number; closed_ms: number | null; reason: string; drop_percent: number }
const { apiFetch, apiUrl } = useApi()
const alerts = shallowRef<Alert[] | null>(null)
const active = computed(() => alerts.value?.filter(a => a.closed_ms === null) ?? [])
const closed = computed(() => alerts.value?.filter(a => a.closed_ms !== null) ?? [])
const error = ref('')
const title = (a: Alert) => a.kind === 'drop_share' ? 'Высокая доля отброшенных пакетов' : 'Измерения XDP перестали поступать'
const date = (ms: number) => new Date(ms).toLocaleString()
const evidence = (a: Alert) => `При открытии отброшено ${a.drop_percent.toLocaleString(undefined, { maximumFractionDigits: 2 })}%. Основная причина: ${xdpDropReasons.find(r => r.key === a.reason)?.label ?? a.reason}.`
let disposed = false
let timer: ReturnType<typeof setTimeout> | undefined
async function refresh() {
  try {
    const data = await apiFetch<{ items: Alert[] }>(apiUrl('/dashboard/xdp/alerts'), { timeout: 10000 })
    if (!disposed) { alerts.value = data.items; error.value = '' }
  } catch { if (!disposed) error.value = 'Не удалось обновить оповещения XDP.' }
  finally { if (!disposed) timer = setTimeout(refresh, 15000) }
}
onMounted(refresh)
onBeforeUnmount(() => { disposed = true; clearTimeout(timer) })
</script>
