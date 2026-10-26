<template>
    <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h4 class="text-sm font-semibold">Статистика XDP <span v-if="interfaceName" class="font-normal text-slate-400">· {{ interfaceName }}</span></h4>
        <span v-if="statistics" class="text-xs text-slate-400">Снимок {{ new Date(statistics.sampled_at).toLocaleTimeString() }} · обновление каждые 10 с</span>
      </div>
      <div v-if="graph" class="mt-4 flex flex-wrap items-center justify-between gap-3">
        <h5 class="text-sm font-semibold">Итоги {{ periodLabel }}</h5>
        <div class="flex gap-2" aria-label="Период статистики XDP">
          <button v-for="option in periods" :key="option.key" type="button" :aria-pressed="period === option.key" class="rounded-lg border px-3 py-1.5 text-xs" :class="period === option.key ? 'border-teal-500 bg-teal-950 text-teal-200' : 'border-slate-600 text-slate-400'" @click="emit('periodChange', option.key)">{{ option.label }}</button>
        </div>
      </div>
      <p v-if="error" role="alert" class="mt-3 text-sm text-amber-300">{{ error }}</p>
      <template v-if="graph">
        <p v-if="historyError" role="alert" class="mt-3 text-xs text-amber-300">{{ historyError }}</p>
        <p v-if="historyLoading && !history" class="mt-3 text-xs text-slate-400">Загрузка итогов и графика…</p>
        <p v-else-if="!historyError && !periodTotals" class="mt-3 text-xs text-slate-400">За выбранный период измерений пока нет. История собирается автоматически, даже когда дашборд закрыт.</p>
        <p v-if="periodTotals && history" class="mt-2 text-xs text-slate-400">{{ new Date(history.from).toLocaleString() }} — {{ new Date(history.to).toLocaleString() }}. Измерено {{ coverage }}. Итоги учитывают только сохранённые измерения, включая предыдущие запуски XDP.</p>
      </template>
      <template v-else>
        <p v-if="!statistics && !error" class="mt-3 text-sm text-slate-400">{{ running ? 'Ожидаются данные счётчиков XDP.' : 'Запустите XDP, чтобы получать статистику.' }}</p>
        <p v-if="statistics?.stale" role="alert" class="mt-3 text-sm text-amber-300">Данные устарели. Скорости не отображаются до получения свежего снимка.</p>
        <p v-if="statistics" class="mt-2 text-xs text-slate-400">Итоги с запуска {{ new Date(statistics.started_at).toLocaleString() }}. При перезапуске счётчики обнуляются.</p>
      </template>
      <template v-if="counters">
        <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Всего пакетов</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(counters.seen) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Пропущено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(counters.passed) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Отброшено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(totalDropped) }} <span class="text-xs text-slate-400">{{ dropPercent }}%</span></p></div>
          <template v-if="graph">
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · объём</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ bytes(counters.frame_bytes) }}</p></div>
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Защищаемые порты · пакеты</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(counters.protected_packets) }}</p></div>
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Защищаемые порты · объём</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ bytes(counters.protected_bytes) }}</p></div>
          </template>
          <template v-else>
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('seen') }}</p></div>
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · Мбит/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('frame_bytes', 8 / 1000000, 2) }}</p></div>
            <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Защищаемые порты · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('protected_packets') }}</p></div>
          </template>
        </div>
        <div v-if="graph" class="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <p>Новые SYN: <strong>{{ number(counters.protected_syn) }}</strong></p>
          <p>Echo Request: <strong>{{ number(counters.icmp_echo) }}</strong></p>
          <p>Средняя скорость: <strong>{{ number(periodTotals?.rates.seen) }}</strong> пакетов/с · <strong>{{ number((periodTotals?.rates.frame_bytes || 0) * 8 / 1000000, 2) }}</strong> Мбит/с</p>
        </div>
        <div v-else class="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <p>Защищаемые порты: <strong>{{ rate('protected_bytes', 8 / 1000000, 2) }}</strong> Мбит/с</p>
          <p>Новые SYN: <strong>{{ rate('protected_syn', 1, 1) }}</strong>/с</p>
          <p>Echo Request: <strong>{{ rate('icmp_echo', 1, 1) }}</strong>/с</p>
        </div>
        <h5 class="mt-5 text-xs font-semibold text-slate-400">Причины отбрасывания<span v-if="graph"> · {{ periodLabel }}</span></h5>
        <div class="mt-3 grid gap-2 sm:grid-cols-2">
          <div v-for="reason in dropReasons" :key="reason.key" class="flex justify-between gap-3 rounded-lg bg-slate-800/50 px-3 py-2 text-xs"><span>{{ reason.label }}</span><span class="font-mono tabular-nums">{{ number(counters[reason.key]) }}</span></div>
        </div>
        <p class="mt-3 text-xs text-slate-400">Неразобранные пакеты, переданные сетевому стеку: {{ number(counters.malformed_pass) }}. Весь входящий трафик интерфейса включает другие сервисы. {{ graph ? 'Средние скорости рассчитаны по времени доступных измерений.' : 'Скорости рассчитаны по разнице двух снимков.' }} Это не HTTP RPS.</p>
      </template>
      <div v-if="graph" class="mt-6 border-t border-white/10 pt-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div><h5 class="text-sm font-semibold">Трафик XDP</h5><p class="mt-1 text-xs text-slate-400">История хранится на сервере 8 дней · средние за {{ history?.step_seconds || 10 }} с по доступным измерениям · пропуски показаны разрывами.</p></div>
          <div class="flex gap-2" aria-label="Единицы графика XDP">
            <button v-for="option in units" :key="option.key" type="button" :aria-pressed="unit === option.key" class="rounded-lg border px-3 py-1.5 text-xs" :class="unit === option.key ? 'border-teal-500 bg-teal-950 text-teal-200' : 'border-slate-600 text-slate-400'" @click="unit = option.key">{{ option.label }}</button>
          </div>
        </div>
        <p v-if="history?.points.length" class="mt-2 text-xs text-slate-400">Последнее измерение: {{ new Date(history.points[history.points.length - 1]!.at).toLocaleString() }}</p>
        <div class="relative mt-4 h-64 sm:h-72"><canvas ref="canvas" role="img" :aria-label="unit === 'packets' ? 'Скорость входящих, защищаемых и отброшенных пакетов XDP' : 'Входящий трафик интерфейса и защищаемых портов в Мбит/с'" /></div>
      </div>
    </div>

</template>

<script setup lang="ts">
import type { Chart } from 'chart.js'
import { xdpChartPoints, xdpDropReasons, xdpDropped, xdpHistoryTotals } from '~/utils/xdpStatistics'
import type { XdpHistory, XdpStatistics, XdpPeriod } from '~/utils/xdpStatistics'

const props = defineProps<{ statistics: XdpStatistics | null; running?: boolean; interfaceName?: string; error?: string; graph?: boolean; history?: XdpHistory | null; historyError?: string; historyLoading?: boolean; period?: XdpPeriod }>()
const emit = defineEmits<{ periodChange: [period: XdpPeriod] }>()
const dropReasons = xdpDropReasons
const periodTotals = computed(() => xdpHistoryTotals(props.history || null))
// Missing history must never fall back to totals from the current program run.
const counters = computed(() => props.graph ? periodTotals.value?.counters : props.statistics?.counters)
const totalDropped = computed(() => xdpDropped(counters.value || {}))
const dropPercent = computed(() => counters.value?.seen ? (100 * totalDropped.value / counters.value.seen).toFixed(2) : '0.00')
const periodLabel = computed(() => props.period === 'week' ? 'за неделю' : props.period === 'day' ? 'за сутки' : 'за час')
const coverage = computed(() => {
  const seconds = Math.round(periodTotals.value?.coverageSeconds || 0)
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor(seconds % 86400 / 3600)
  const minutes = Math.floor(seconds % 3600 / 60)
  return [days && `${days} д`, hours && `${hours} ч`, minutes && `${minutes} мин`, `${seconds % 60} с`].filter(Boolean).join(' ')
})
function bytes(value = 0) {
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
  const index = value > 0 ? Math.min(Math.floor(Math.log10(value) / 3), units.length - 1) : 0
  return `${number(value / 1000 ** index, index ? 2 : 0)} ${units[index]}`
}
function number(value: number | undefined, digits = 0) { return (value || 0).toLocaleString(undefined, { maximumFractionDigits: digits }) }
function rate(key: string, scale = 1, digits = 0) {
  const stats = props.statistics
  return stats && !stats.stale && stats.interval_seconds > 0 && Number.isFinite(stats.rates[key]) ? number(stats.rates[key]! * scale, digits) : '—'
}

const units = [{ key: 'packets', label: 'Пакетов/с' }, { key: 'bandwidth', label: 'Мбит/с' }] as const
const unit = ref<'packets' | 'bandwidth'>('packets')
const periods = [{ key: 'hour', label: 'Час' }, { key: 'day', label: 'Сутки' }, { key: 'week', label: 'Неделя' }] as const
const points = computed(() => xdpChartPoints(props.history || null))
const canvas = ref<HTMLCanvasElement | null>(null)
let chart: Chart<'line'> | null = null
let disposed = false

function formatTime(value: number) {
  const date = new Date(value)
  return props.period === 'hour' ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : date.toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}
function renderChart() {
  if (!chart) return
  const series = unit.value === 'packets'
    ? [{ key: 'seen', label: 'Весь интерфейс', color: '#38bdf8' }, { key: 'protected_packets', label: 'Защищаемые порты', color: '#2dd4bf' }, { key: 'dropped', label: 'Отброшено', color: '#fb7185' }]
    : [{ key: 'frame_bytes', label: 'Весь интерфейс', color: '#38bdf8' }, { key: 'protected_bytes', label: 'Защищаемые порты', color: '#2dd4bf' }]
  const scale = unit.value === 'packets' ? 1 : 8 / 1000000
  chart.data.datasets = series.map(s => Object.assign(chart!.data.datasets.find(dataset => dataset.label === s.label) || {}, {
    label: s.label,
    data: points.value.map(p => ({ x: p.at, y: p.rates && Number.isFinite(p.rates[s.key]) ? p.rates[s.key]! * scale : null })) as any,
    borderColor: s.color, backgroundColor: s.color, borderWidth: 2, pointRadius: 2, pointHoverRadius: 4, spanGaps: false,
  }))
  if (chart.options.scales?.y?.title) chart.options.scales.y.title.text = unit.value === 'packets' ? 'Пакетов/с' : 'Мбит/с'
  if (chart.options.scales?.x) {
    const end = props.history ? Date.parse(props.history.to) : Date.now()
    const duration = props.period === 'week' ? 7 * 86400000 : props.period === 'day' ? 86400000 : 3600000
    chart.options.scales.x.min = props.history ? Date.parse(props.history.from) : end - duration
    chart.options.scales.x.max = end
  }
  chart.update('none')
}
watch([() => props.history, () => props.period], renderChart)
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
          title: items => items.length ? new Date(items[0]!.parsed.x).toLocaleString() : '',
          label: item => `${item.dataset.label}: ${number(item.parsed.y ?? undefined, 2)} ${unit.value === 'packets' ? 'пакетов/с' : 'Мбит/с'}`,
        } },
      },
      scales: {
        x: { type: 'linear', ticks: { color: '#94a3b8', maxTicksLimit: 6, callback: value => formatTime(Number(value)) }, grid: { color: 'rgba(148,163,184,0.08)' } },
        y: { beginAtZero: true, title: { display: true, text: 'Пакетов/с', color: '#94a3b8' }, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.08)' } },
      },
    },
  })
  renderChart()
})
onBeforeUnmount(() => { disposed = true; chart?.destroy(); chart = null })
</script>
