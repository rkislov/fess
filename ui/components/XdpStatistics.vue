<template>
    <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h4 class="text-sm font-semibold">Статистика XDP <span v-if="interfaceName" class="font-normal text-slate-400">· {{ interfaceName }}</span></h4>
        <span v-if="statistics" class="text-xs text-slate-400">Снимок {{ new Date(statistics.sampled_at).toLocaleTimeString() }} · обновление каждые 10 с</span>
      </div>
      <p v-if="error" role="alert" class="mt-3 text-sm text-amber-300">{{ error }}</p>
      <p v-if="!statistics" class="mt-3 text-sm text-slate-400">{{ running ? 'Ожидаются данные счётчиков XDP.' : 'Запустите XDP, чтобы получать статистику.' }}</p>
      <template v-else>
        <p v-if="statistics.stale" role="alert" class="mt-3 text-sm text-amber-300">Данные устарели. Скорости не отображаются до получения свежего снимка.</p>
        <p class="mt-2 text-xs text-slate-400">Итоги с запуска {{ new Date(statistics.started_at).toLocaleString() }}. При перезапуске счётчики обнуляются. Весь входящий трафик интерфейса включает другие сервисы.</p>
        <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Всего пакетов</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(statistics.counters.seen) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Пропущено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(statistics.counters.passed) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Отброшено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(totalDropped) }} <span class="text-xs text-slate-400">{{ dropPercent }}%</span></p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('seen') }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · Мбит/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('frame_bytes', 8 / 1000000, 2) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Защищаемые порты · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('protected_packets') }}</p></div>
        </div>
        <div class="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <p>Защищаемые порты: <strong>{{ rate('protected_bytes', 8 / 1000000, 2) }}</strong> Мбит/с</p>
          <p>Новые SYN: <strong>{{ rate('protected_syn', 1, 1) }}</strong>/с</p>
          <p>Echo Request: <strong>{{ rate('icmp_echo', 1, 1) }}</strong>/с</p>
        </div>
        <h5 class="mt-5 text-xs font-semibold text-slate-400">Причины отбрасывания</h5>
        <div class="mt-3 grid gap-2 sm:grid-cols-2">
          <div v-for="reason in dropReasons" :key="reason.key" class="flex justify-between gap-3 rounded-lg bg-slate-800/50 px-3 py-2 text-xs"><span>{{ reason.label }}</span><span class="font-mono tabular-nums">{{ number(statistics.counters[reason.key]) }}</span></div>
        </div>
        <p class="mt-3 text-xs text-slate-400">Неразобранные пакеты, переданные сетевому стеку: {{ number(statistics.counters.malformed_pass) }}. Скорости рассчитаны по разнице двух снимков, это не HTTP RPS.</p>
      </template>
      <div v-if="graph" class="mt-6 border-t border-white/10 pt-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div><h5 class="text-sm font-semibold">Трафик XDP</h5><p class="mt-1 text-xs text-slate-400">Последние 15 минут, пока открыт дашборд · снимки каждые 10 с · пропуски данных показаны разрывами.</p></div>
          <div class="flex gap-2" aria-label="Единицы графика XDP">
            <button v-for="option in units" :key="option.key" type="button" :aria-pressed="unit === option.key" class="rounded-lg border px-3 py-1.5 text-xs" :class="unit === option.key ? 'border-teal-500 bg-teal-950 text-teal-200' : 'border-slate-600 text-slate-400'" @click="unit = option.key">{{ option.label }}</button>
          </div>
        </div>
        <p v-if="!history.length" class="mt-3 text-xs text-slate-400">Ожидаются два свежих снимка для расчёта скорости.</p>
        <div class="relative mt-4 h-64 sm:h-72"><canvas ref="canvas" role="img" :aria-label="unit === 'packets' ? 'Скорость входящих, защищаемых и отброшенных пакетов XDP' : 'Входящий трафик интерфейса и защищаемых портов в Мбит/с'" /></div>
      </div>
    </div>

</template>

<script setup lang="ts">
import type { Chart } from 'chart.js'
import { appendXdpSample, xdpDropReasons, xdpDropped } from '~/utils/xdpStatistics'
import type { XdpHistory, XdpStatistics } from '~/utils/xdpStatistics'

const props = defineProps<{ statistics: XdpStatistics | null; running?: boolean; interfaceName?: string; error?: string; graph?: boolean }>()
const dropReasons = xdpDropReasons
const totalDropped = computed(() => xdpDropped(props.statistics?.counters || {}))
const dropPercent = computed(() => props.statistics?.counters.seen ? (100 * totalDropped.value / props.statistics.counters.seen).toFixed(2) : '0.00')
function number(value: number | undefined, digits = 0) { return (value || 0).toLocaleString(undefined, { maximumFractionDigits: digits }) }
function rate(key: string, scale = 1, digits = 0) {
  const stats = props.statistics
  return stats && !stats.stale && stats.interval_seconds > 0 && Number.isFinite(stats.rates[key]) ? number(stats.rates[key]! * scale, digits) : '—'
}

const units = [{ key: 'packets', label: 'Пакетов/с' }, { key: 'bandwidth', label: 'Мбит/с' }] as const
const unit = ref<'packets' | 'bandwidth'>('packets')
const state = shallowRef<XdpHistory>({ source: '', points: [] })
const history = computed(() => state.value.points)
const canvas = ref<HTMLCanvasElement | null>(null)
let chart: Chart<'line'> | null = null
let disposed = false

function renderChart() {
  if (!chart) return
  const series = unit.value === 'packets'
    ? [{ key: 'seen', label: 'Весь интерфейс', color: '#38bdf8' }, { key: 'protected_packets', label: 'Защищаемые порты', color: '#2dd4bf' }, { key: 'dropped', label: 'Отброшено', color: '#fb7185' }]
    : [{ key: 'frame_bytes', label: 'Весь интерфейс', color: '#38bdf8' }, { key: 'protected_bytes', label: 'Защищаемые порты', color: '#2dd4bf' }]
  const scale = unit.value === 'packets' ? 1 : 8 / 1000000
  chart.data.datasets = series.map(s => ({
    label: s.label,
    data: history.value.map(p => ({ x: p.at, y: p.rates && Number.isFinite(p.rates[s.key]) ? p.rates[s.key]! * scale : null })) as any,
    borderColor: s.color, backgroundColor: s.color, borderWidth: 2, pointRadius: 2, pointHoverRadius: 4, spanGaps: false,
  }))
  if (chart.options.scales?.y?.title) chart.options.scales.y.title.text = unit.value === 'packets' ? 'Пакетов/с' : 'Мбит/с'
  if (chart.options.scales?.x) {
    const end = history.value.at(-1)?.at || Date.now()
    chart.options.scales.x.min = end - 15 * 60 * 1000
    chart.options.scales.x.max = end
  }
  chart.update('none')
}
watch(() => props.statistics, sample => {
  if (!props.graph) return
  if (sample) state.value = appendXdpSample(state.value, sample)
  else state.value = { source: '', points: [] }
  renderChart()
}, { immediate: true })
watch(unit, renderChart)
onMounted(async () => {
  if (!props.graph) return
  const { Chart, LineController, LineElement, PointElement, LinearScale, Legend, Tooltip } = await import('chart.js')
  if (disposed || !canvas.value) return
  Chart.register(LineController, LineElement, PointElement, LinearScale, Legend, Tooltip)
  chart = new Chart(canvas.value, {
    type: 'line', data: { datasets: [] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#94a3b8', usePointStyle: true, boxWidth: 8 } },
        tooltip: { callbacks: {
          title: items => items.length ? new Date(items[0]!.parsed.x).toLocaleTimeString() : '',
          label: item => `${item.dataset.label}: ${number(item.parsed.y ?? undefined, 2)} ${unit.value === 'packets' ? 'пакетов/с' : 'Мбит/с'}`,
        } },
      },
      scales: {
        x: { type: 'linear', ticks: { color: '#94a3b8', maxTicksLimit: 6, callback: value => new Date(Number(value)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }, grid: { color: 'rgba(148,163,184,0.08)' } },
        y: { beginAtZero: true, title: { display: true, text: 'Пакетов/с', color: '#94a3b8' }, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.08)' } },
      },
    },
  })
  renderChart()
})
onBeforeUnmount(() => { disposed = true; chart?.destroy(); chart = null })
</script>
