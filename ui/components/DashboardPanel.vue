<template>
  <div class="space-y-8">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-medium text-slate-300">География (по странам клиентов)</h3>
      <p class="mt-1 text-xs text-slate-500">
        Круги — приблизительные центроиды стран; радиус и насыщенность по числу соединений. Нужны GeoIP (MMDB) или заголовок CF-IPCountry на шлюзе.
      </p>
      <div ref="elMap" class="mt-4 h-[420px] w-full overflow-hidden rounded-xl border border-slate-700/80" />
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 class="text-lg font-semibold text-white">Дашборд трафика и защиты</h2>
          <p class="mt-1 text-sm text-slate-400">
            Агрегаты по журналу соединений и срабатываниям WAF за выбранный период. Данные можно подгружать автоматически (по умолчанию раз в минуту; интервал настраивается и сохраняется в браузере).
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          <label class="flex items-center gap-2 text-sm text-slate-300">
            <span>Период</span>
            <select
              v-model.number="hours"
              class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-white"
            >
              <option :value="6">6 ч</option>
              <option :value="24">24 ч</option>
              <option :value="72">3 суток</option>
              <option :value="168">7 суток</option>
            </select>
          </label>
          <label class="flex items-center gap-2 text-sm text-slate-300">
            <span>Автообновление</span>
            <select
              v-model.number="autoRefreshSec"
              class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-white"
            >
              <option v-for="o in refreshOptions" :key="o.sec" :value="o.sec">{{ o.label }}</option>
            </select>
          </label>
          <button
            type="button"
            class="rounded-lg bg-gradient-to-r from-teal-600 to-emerald-600 px-4 py-2 text-sm font-medium text-white shadow-md hover:from-teal-500 hover:to-emerald-500 disabled:opacity-50"
            :disabled="busy"
            @click="load"
          >
            {{ busy ? 'Загрузка…' : 'Обновить' }}
          </button>
        </div>
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-inner">
      <div class="mb-3">
        <h3 class="text-sm font-medium text-slate-300">Трафик (RPS)</h3>
        <p class="mt-1 text-xs text-slate-500">
          Средняя интенсивность запросов в секунду по журналу соединений (усреднение по интервалу
          <span class="font-mono text-slate-400">{{ rpsBucketHint }}</span>).
        </p>
      </div>
      <p v-if="summary && !(summary.rps_series?.length)" class="mb-2 text-center text-xs text-slate-500">
        Нет записей за выбранный период — график появится после трафика через шлюз.
      </p>
      <div class="relative h-64 w-full sm:h-72">
        <canvas ref="elRps"></canvas>
      </div>
    </section>

    <div class="grid gap-6 lg:grid-cols-2">
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-4 shadow-inner">
        <h3 class="mb-3 text-sm font-medium text-slate-300">Топ виртуальных хостов</h3>
        <div class="relative h-72 w-full">
          <canvas ref="elHost"></canvas>
        </div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-4 shadow-inner">
        <h3 class="mb-3 text-sm font-medium text-slate-300">HTTP-методы</h3>
        <div class="relative mx-auto h-72 max-w-sm">
          <canvas ref="elMethod"></canvas>
        </div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-4 shadow-inner">
        <h3 class="mb-3 text-sm font-medium text-slate-300">Протокол</h3>
        <div class="relative mx-auto h-56 max-w-xs">
          <canvas ref="elProto"></canvas>
        </div>
      </div>
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-4 shadow-inner">
        <h3 class="mb-3 text-sm font-medium text-slate-300">Итог соединения</h3>
        <div class="relative mx-auto h-56 max-w-xs">
          <canvas ref="elOutcome"></canvas>
        </div>
      </div>
    </div>

    <div class="grid gap-6 lg:grid-cols-2">
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <h3 class="text-sm font-semibold text-white">Топ действий WAF</h3>
        <p class="mt-0.5 text-xs text-slate-500">По журналу правил за период</p>
        <ul class="mt-4 space-y-2 text-sm">
          <li v-if="!summary?.top_waf_actions?.length" class="text-slate-500">Нет записей</li>
          <li
            v-for="(r, i) in summary?.top_waf_actions"
            :key="'a' + i"
            class="flex justify-between gap-3 rounded-lg bg-slate-800/60 px-3 py-2 font-mono text-xs"
          >
            <span class="text-teal-300/90">{{ labelWafAction(r.action) }}</span>
            <span class="text-slate-300">{{ r.count }}</span>
          </li>
        </ul>
      </section>
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <h3 class="text-sm font-semibold text-white">Топ срабатываний по правилу</h3>
        <p class="mt-0.5 text-xs text-slate-500">rule_id + действие</p>
        <ul class="mt-4 space-y-2 text-sm">
          <li v-if="!summary?.top_waf_rules?.length" class="text-slate-500">Нет записей</li>
          <li
            v-for="(r, i) in summary?.top_waf_rules"
            :key="'r' + i"
            class="flex flex-col gap-0.5 rounded-lg bg-slate-800/60 px-3 py-2 font-mono text-xs sm:flex-row sm:items-center sm:justify-between"
          >
            <span class="truncate text-slate-300" :title="r.rule_id || '—'">{{ r.rule_id || '—' }}</span>
            <span class="text-teal-300/90">{{ labelWafAction(r.action) }}</span>
            <span class="text-slate-400">{{ r.count }}</span>
          </li>
        </ul>
      </section>
    </div>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Страны (таблица)</h3>
      <div class="mt-3 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="py-2 pr-3">Код</th>
              <th class="py-2">Соединений</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!countryRows.length">
              <td colspan="2" class="py-6 text-center text-slate-500">Нет данных по странам за период</td>
            </tr>
            <tr v-for="c in countryRows" :key="c.country_code" class="border-b border-slate-800/80">
              <td class="py-2 pr-3 font-mono">{{ c.country_code }}</td>
              <td class="py-2">{{ c.count }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { Map as LeafMap, CircleMarker } from 'leaflet'
import type { Chart as ChartType } from 'chart.js'

const { apiUrl } = useApi()

type CountRow = { key: string; count: number }
type HostRow = { host: string; count: number }
type CountryRow = { country_code: string; count: number; lat: number; lon: number }
type WafAction = { action: string; count: number }
type WafRule = { rule_id: string; action: string; count: number }
type RpsPoint = { bucket_start: string; bucket_seconds: number; count: number; rps: number }

type Summary = {
  period_hours: number
  since: string
  by_host: HostRow[]
  by_method: CountRow[]
  by_protocol: CountRow[]
  by_outcome: CountRow[]
  by_country: CountryRow[]
  top_waf_actions: WafAction[]
  top_waf_rules: WafRule[]
  rps_series?: RpsPoint[]
  rps_bucket_seconds?: number
  rps_bucket_interval?: string
}

const hours = ref(24)
const busy = ref(false)
const err = ref('')
const summary = ref<Summary | null>(null)

const REFRESH_LS_KEY = 'fence_dashboard_refresh_sec'
const refreshOptions = [
  { sec: 0, label: 'Выкл' },
  { sec: 30, label: '30 с' },
  { sec: 60, label: '1 мин' },
  { sec: 120, label: '2 мин' },
  { sec: 300, label: '5 мин' },
] as const
const allowedRefresh = new Set<number>(refreshOptions.map((o) => o.sec))

function readStoredRefreshSec(): number {
  if (!import.meta.client) return 60
  try {
    const raw = localStorage.getItem(REFRESH_LS_KEY)
    if (raw == null) return 60
    const n = parseInt(raw, 10)
    if (!Number.isNaN(n) && allowedRefresh.has(n)) return n
  } catch {
    /* ignore */
  }
  return 60
}

const autoRefreshSec = ref(60)

let refreshTimer: ReturnType<typeof setInterval> | null = null

function clearRefreshTimer() {
  if (refreshTimer != null) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

function startRefreshTimer() {
  clearRefreshTimer()
  if (!import.meta.client || autoRefreshSec.value <= 0) return
  refreshTimer = setInterval(() => {
    if (!busy.value) void load()
  }, autoRefreshSec.value * 1000)
}

const elHost = ref<HTMLCanvasElement | null>(null)
const elMethod = ref<HTMLCanvasElement | null>(null)
const elProto = ref<HTMLCanvasElement | null>(null)
const elOutcome = ref<HTMLCanvasElement | null>(null)
const elRps = ref<HTMLCanvasElement | null>(null)
const elMap = ref<HTMLDivElement | null>(null)

let chartHost: ChartType | null = null
let chartMethod: ChartType | null = null
let chartProto: ChartType | null = null
let chartOutcome: ChartType | null = null
let chartRps: ChartType | null = null
let mapInst: LeafMap | null = null
const markers: CircleMarker[] = []

let chartPrepared = false

const countryRows = computed(() => summary.value?.by_country || [])

const rpsBucketHint = computed(() => {
  const raw = summary.value?.rps_bucket_interval || ''
  const m: Record<string, string> = {
    '1 minute': '1 минута',
    '5 minutes': '5 минут',
    '15 minutes': '15 минут',
    '1 hour': '1 час',
  }
  return m[raw] || raw || '—'
})

function fmtBucketLabel(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function labelWafAction(a: string) {
  const m: Record<string, string> = {
    allow: 'allow',
    block: 'block',
    log: 'log',
    redirect: 'redirect',
    replace: 'replace',
  }
  return m[a] || a
}

function destroyCharts() {
  chartHost?.destroy()
  chartMethod?.destroy()
  chartProto?.destroy()
  chartOutcome?.destroy()
  chartRps?.destroy()
  chartHost = null
  chartMethod = null
  chartProto = null
  chartOutcome = null
  chartRps = null
}

function tealPalette(i: number, n: number) {
  const t = n <= 1 ? 0.5 : i / (n - 1)
  const r = Math.round(20 + t * 80)
  const g = Math.round(180 + t * 75)
  const b = Math.round(160 + t * 95)
  return `rgb(${r},${g},${b})`
}

async function ensureChartLib() {
  if (chartPrepared || !import.meta.client) return
  const {
    ArcElement,
    BarController,
    BarElement,
    CategoryScale,
    Chart,
    DoughnutController,
    Filler,
    Legend,
    LinearScale,
    LineController,
    LineElement,
    PointElement,
    Tooltip,
  } = await import('chart.js')
  Chart.register(
    BarController,
    BarElement,
    CategoryScale,
    LinearScale,
    DoughnutController,
    ArcElement,
    LineController,
    LineElement,
    PointElement,
    Filler,
    Legend,
    Tooltip,
  )
  chartPrepared = true
}

async function buildBar(canvas: HTMLCanvasElement, labels: string[], data: number[], title: string) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: title,
          data,
          backgroundColor: labels.map((_, i) => tealPalette(i, labels.length)),
          borderWidth: 0,
        },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.12)' } },
        y: { ticks: { color: '#cbd5e1', maxRotation: 0 }, grid: { display: false } },
      },
    },
  })
}

async function buildLineRps(canvas: HTMLCanvasElement, labels: string[], data: number[]) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  return new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'RPS',
          data,
          fill: true,
          backgroundColor: 'rgba(45, 212, 191, 0.12)',
          borderColor: 'rgb(45, 212, 191)',
          borderWidth: 2,
          tension: 0.2,
          pointRadius: 0,
          pointHoverRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true, labels: { color: '#cbd5e1' } },
        tooltip: {
          callbacks: {
            label(ctx) {
              const v = typeof ctx.raw === 'number' ? ctx.raw : 0
              return ` ${v.toFixed(3)} запр./с`
            },
          },
        },
      },
      scales: {
        x: {
          ticks: {
            color: '#94a3b8',
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 14,
          },
          grid: { color: 'rgba(148,163,184,0.08)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#94a3b8' },
          grid: { color: 'rgba(148,163,184,0.12)' },
        },
      },
    },
  })
}

async function buildDoughnut(canvas: HTMLCanvasElement, labels: string[], data: number[]) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  return new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [
        {
          data,
          backgroundColor: labels.map((_, i) => tealPalette(i, labels.length)),
          borderWidth: 1,
          borderColor: '#0f172a',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#cbd5e1', boxWidth: 12 } },
      },
    },
  })
}

function labelOutcome(o: string) {
  const m: Record<string, string> = {
    proxied: 'Прокси',
    waf_block: 'Блок WAF',
    redirect: 'Редирект',
    malware_block: 'Антивирус',
  }
  return m[o] || o
}

async function renderRpsChart(s: Summary) {
  if (!import.meta.client) return
  chartRps?.destroy()
  chartRps = null
  await nextTick()
  const ser = s.rps_series || []
  if (!elRps.value || !ser.length) return
  const labels = ser.map((p) => fmtBucketLabel(p.bucket_start))
  const data = ser.map((p) => p.rps)
  chartRps = await buildLineRps(elRps.value, labels, data)
}

async function renderCharts(s: Summary) {
  if (!import.meta.client) return
  destroyCharts()
  await nextTick()
  if (elHost.value && s.by_host?.length) {
    chartHost = await buildBar(
      elHost.value,
      s.by_host.map((x) => x.host || '—'),
      s.by_host.map((x) => x.count),
      'Запросы',
    )
  }
  if (elMethod.value && s.by_method?.length) {
    chartMethod = await buildDoughnut(
      elMethod.value,
      s.by_method.map((x) => x.key || '—'),
      s.by_method.map((x) => x.count),
    )
  }
  if (elProto.value && s.by_protocol?.length) {
    chartProto = await buildDoughnut(
      elProto.value,
      s.by_protocol.map((x) => (x.key === 'https' ? 'HTTPS' : x.key === 'http' ? 'HTTP' : x.key || '—')),
      s.by_protocol.map((x) => x.count),
    )
  }
  if (elOutcome.value && s.by_outcome?.length) {
    chartOutcome = await buildDoughnut(
      elOutcome.value,
      s.by_outcome.map((x) => labelOutcome(x.key)),
      s.by_outcome.map((x) => x.count),
    )
  }
}

async function renderMap(rows: CountryRow[]) {
  if (!import.meta.client || !elMap.value) return
  const L = (await import('leaflet')).default
  await import('leaflet/dist/leaflet.css')

  for (const m of markers) {
    try {
      m.remove()
    } catch {
      /* ignore */
    }
  }
  markers.length = 0
  mapInst?.remove()
  mapInst = null

  const pts = rows.filter((r) => r.lat !== 0 || r.lon !== 0)
  if (!pts.length) {
    elMap.value.innerHTML =
      '<div class="flex h-full items-center justify-center text-sm text-slate-500">Нет координат для карты (нет кодов стран или неизвестные коды)</div>'
    return
  }

  const map = L.map(elMap.value, { scrollWheelZoom: false, worldCopyJump: true }).setView([20, 0], 2)
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 19,
  }).addTo(map)
  mapInst = map

  const maxC = Math.max(...pts.map((p) => p.count), 1)
  for (const p of pts) {
    const t = p.count / maxC
    const radius = 6 + t * 28
    const cm = L.circleMarker([p.lat, p.lon], {
      radius,
      color: '#2dd4bf',
      weight: 1,
      fillColor: '#f43f5e',
      fillOpacity: 0.35 + t * 0.45,
    })
    cm.bindTooltip(`${p.country_code}: ${p.count}`)
    cm.addTo(map)
    markers.push(cm)
  }

  try {
    const b = L.latLngBounds(pts.map((p) => [p.lat, p.lon] as [number, number]))
    map.fitBounds(b.pad(0.15))
  } catch {
    map.setView([pts[0].lat, pts[0].lon], 3)
  }
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const q = new URLSearchParams({ hours: String(hours.value) })
    const data = await $fetch<Summary>(`${apiUrl('/dashboard/summary')}?${q}`)
    summary.value = data
    await renderCharts(data)
    await renderRpsChart(data)
    await renderMap(data.by_country || [])
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  if (!import.meta.client) return
  autoRefreshSec.value = readStoredRefreshSec()
  void load()
  startRefreshTimer()
})

watch(autoRefreshSec, () => {
  if (import.meta.client) {
    try {
      localStorage.setItem(REFRESH_LS_KEY, String(autoRefreshSec.value))
    } catch {
      /* ignore */
    }
  }
  startRefreshTimer()
})

onBeforeUnmount(() => {
  clearRefreshTimer()
  destroyCharts()
  mapInst?.remove()
  mapInst = null
  markers.length = 0
})
</script>
