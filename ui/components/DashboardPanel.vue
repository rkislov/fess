<template>
  <div class="space-y-8">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-medium text-slate-300">География (по странам клиентов)</h3>
      <p class="mt-1 text-xs text-slate-500">
        Круги — приблизительные центроиды стран; радиус и насыщенность по числу соединений. Нужен код страны в логах: установите MMDB в <span class="font-mono text-slate-400">Malware → GeoIP</span> или задайте путь на шлюзе; альтернатива — <span class="font-mono text-slate-400">CF-IPCountry</span>.
      </p>
      <div ref="elMap" class="mt-4 h-[420px] w-full overflow-hidden rounded-xl border border-slate-700/80" />
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <div class="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between lg:gap-8">
        <div class="min-w-0 flex-1">
          <h2 class="text-lg font-semibold text-white">Дашборд трафика и защиты</h2>
          <p class="mt-1 max-w-2xl text-sm leading-relaxed text-slate-400">
            Агрегаты по журналу соединений и срабатываниям WAF за выбранный период. Данные можно подгружать автоматически (по умолчанию раз в минуту; интервал настраивается и сохраняется в браузере).
          </p>
        </div>
        <div
          class="grid shrink-0 grid-cols-[auto_minmax(0,11rem)] grid-rows-[auto_auto_auto] items-center gap-x-3 gap-y-2.5 sm:min-w-[15rem]"
          aria-label="Параметры дашборда"
        >
          <span class="justify-self-end self-center text-sm text-slate-300">Период</span>
          <select
            v-model.number="hours"
            class="h-10 w-full rounded-lg border border-slate-600 bg-slate-800 px-3 text-sm text-white"
          >
            <option :value="6">6 ч</option>
            <option :value="24">24 ч</option>
            <option :value="72">3 суток</option>
            <option :value="168">7 суток</option>
          </select>
          <span class="justify-self-end self-center text-sm text-slate-300">Автообновление</span>
          <select
            v-model.number="autoRefreshSec"
            class="h-10 w-full rounded-lg border border-slate-600 bg-slate-800 px-3 text-sm text-white"
          >
            <option v-for="o in refreshOptions" :key="o.sec" :value="o.sec">{{ o.label }}</option>
          </select>
          <button
            type="button"
            class="col-start-2 row-start-3 h-10 w-full rounded-lg bg-gradient-to-r from-teal-600 to-emerald-600 px-4 text-sm font-medium text-white shadow-md hover:from-teal-500 hover:to-emerald-500 disabled:opacity-50"
            :disabled="busy"
            @click="load"
          >
            {{ busy ? 'Загрузка…' : 'Обновить' }}
          </button>
        </div>
      </div>
    </section>

    <section class="grid gap-4 sm:grid-cols-2">
      <div class="rounded-2xl border border-emerald-600/25 bg-slate-900/60 p-5">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Внутренний антивирус (ICAP)</h3>
            <p class="mt-0.5 text-xs text-slate-500">ClamAV / ICAP — проверенные тела запросов за период</p>
          </div>
          <span class="text-lg" aria-hidden="true">🛡️</span>
        </div>
        <p class="mt-4 font-mono text-3xl font-semibold tabular-nums text-emerald-300">
          {{ fmtCount(malwareScans.icap_checked) }}
        </p>
        <p v-if="malwareScans.blocked > 0" class="mt-1 text-xs text-slate-500">
          Угроз по журналу:
          <span class="font-mono text-rose-300/90">{{ fmtCount(malwareScans.blocked) }}</span>
          (все источники)
        </p>
      </div>
      <div class="rounded-2xl border border-violet-600/25 bg-slate-900/60 p-5">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Сторонний сканер</h3>
            <p class="mt-0.5 text-xs text-slate-500">HTTP-сканер (THOR Lite и др.) — проверенные файлы за период</p>
          </div>
          <span class="text-lg" aria-hidden="true">🔬</span>
        </div>
        <p class="mt-4 font-mono text-3xl font-semibold tabular-nums text-violet-300">
          {{ fmtCount(malwareScans.external_checked) }}
        </p>
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-inner">
      <div class="mb-3">
        <h3 class="text-sm font-medium text-slate-300">Трафик и срабатывания (RPS)</h3>
        <p class="mt-1 text-xs text-slate-500">
          Интенсивность запросов в секунду по интервалу
          <span class="font-mono text-slate-400">{{ rpsBucketHint }}</span>.
          Клик по плашке легенды — скрыть или показать линию.
        </p>
      </div>
      <div v-if="trafficSeriesMeta.length" class="mb-4 flex flex-wrap gap-2">
        <button
          v-for="s in trafficSeriesMeta"
          :key="s.id"
          type="button"
          class="flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition"
          :class="
            seriesVisible[s.id] !== false
              ? 'border-slate-600/80 bg-slate-800/80 text-slate-200'
              : 'border-slate-800 bg-slate-950/60 text-slate-500 line-through opacity-70'
          "
          :title="seriesVisible[s.id] !== false ? 'Скрыть с графика' : 'Показать на графике'"
          @click="toggleTrafficSeries(s.id)"
        >
          <span class="h-2.5 w-2.5 shrink-0 rounded-sm border border-black/20" :style="{ backgroundColor: s.color }" />
          {{ s.label }}
        </button>
      </div>
      <p v-if="summary && !hasTrafficChartData" class="mb-2 text-center text-xs text-slate-500">
        Нет записей за выбранный период — график появится после трафика через шлюз.
      </p>
      <div class="relative h-64 w-full sm:h-80">
        <canvas ref="elRps"></canvas>
      </div>
    </section>

    <div class="grid gap-6 lg:grid-cols-2">
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Топ виртуальных хостов</h3>
            <p class="mt-0.5 text-xs text-slate-500">
              Топ‑10 за период
              <template v-if="hostsHiddenCount > 0"> · ещё {{ hostsHiddenCount }} — по кнопке ниже</template>
            </p>
          </div>
          <span v-if="summary?.hosts_total" class="font-mono text-xs text-slate-500">{{ summary.hosts_total }} всего</span>
        </div>
        <p v-if="summary && !visibleHostRows.length" class="mt-4 text-sm text-slate-500">Нет записей</p>
        <div
          v-else
          class="relative mt-4 w-full"
          :style="{ height: `${barChartHeight(visibleHostRows.length)}px` }"
        >
          <canvas ref="elHost"></canvas>
        </div>
        <button
          v-if="hostsHiddenCount > 0"
          type="button"
          class="mt-3 w-full rounded-lg border border-teal-600/40 bg-teal-950/40 px-3 py-2 text-xs font-medium text-teal-200 hover:bg-teal-900/50"
          @click="hostsExpanded = !hostsExpanded"
        >
          {{ hostsExpanded ? 'Свернуть до топ‑10' : `Показать ещё ${hostsHiddenCount} хостов` }}
        </button>
      </section>
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
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <h3 class="mb-1 text-sm font-semibold text-white">Итог соединения</h3>
        <p class="mb-3 text-xs text-slate-500">Клик по плашке — скрыть сегмент на диаграмме</p>
        <div v-if="outcomeLegendItems.length" class="mb-3 flex flex-wrap gap-2">
          <button
            v-for="item in outcomeLegendItems"
            :key="item.key"
            type="button"
            class="flex items-center gap-1.5 rounded-lg border px-2 py-1 text-xs transition"
            :class="
              outcomeVisible[item.key] !== false
                ? 'border-slate-600/80 bg-slate-800/80 text-slate-200'
                : 'border-slate-800 bg-slate-950/60 text-slate-500 line-through opacity-70'
            "
            @click="toggleOutcomeSlice(item.key)"
          >
            <span class="h-2.5 w-2.5 rounded-sm border border-black/20" :style="{ backgroundColor: item.color }" />
            {{ item.label }}
          </button>
        </div>
        <div class="relative mx-auto h-56 max-w-xs">
          <canvas ref="elOutcome"></canvas>
        </div>
      </section>
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 lg:col-span-2">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Топ User-Agent</h3>
            <p class="mt-0.5 text-xs text-slate-500">
              Топ‑10 за период · длинные строки сокращены на оси, полный текст — в подсказке
              <template v-if="uaHiddenCount > 0"> · ещё {{ uaHiddenCount }} — по кнопке ниже</template>
            </p>
          </div>
        </div>
        <p v-if="summary && !visibleUARows.length" class="mt-4 text-sm text-slate-500">Нет записей</p>
        <div
          v-else
          class="relative mt-4 w-full"
          :style="{ height: `${barChartHeight(visibleUARows.length)}px` }"
        >
          <canvas ref="elUA"></canvas>
        </div>
        <button
          v-if="uaHiddenCount > 0"
          type="button"
          class="mt-3 w-full rounded-lg border border-teal-600/40 bg-teal-950/40 px-3 py-2 text-xs font-medium text-teal-200 hover:bg-teal-900/50"
          @click="uaExpanded = !uaExpanded"
        >
          {{ uaExpanded ? 'Свернуть до топ‑10' : `Показать ещё ${uaHiddenCount} User-Agent` }}
        </button>
      </section>
    </div>

    <div class="grid gap-6 lg:grid-cols-2">
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Топ действий WAF</h3>
            <p class="mt-0.5 text-xs text-slate-500">Топ‑10 за период · клик — все события с этим действием</p>
          </div>
          <button
            type="button"
            class="shrink-0 rounded-lg border border-teal-600/40 bg-teal-950/40 px-3 py-1.5 text-xs font-medium text-teal-200 hover:bg-teal-900/50"
            @click="openAllWafEvents"
          >
            Далее →
          </button>
        </div>
        <ul class="mt-4 space-y-2 text-sm">
          <li v-if="!topWafActions.length" class="text-slate-500">Нет записей</li>
          <li
            v-for="(a, i) in topWafActions"
            :key="'a' + i"
            class="flex cursor-pointer flex-col gap-1 rounded-lg bg-slate-800/60 px-3 py-2 text-xs transition hover:bg-slate-700/80 sm:flex-row sm:items-center sm:justify-between"
            role="button"
            tabindex="0"
            @click="openActionHits(a)"
            @keydown.enter="openActionHits(a)"
          >
            <span class="min-w-0 flex-1 font-medium text-slate-200" :title="a.action">
              {{ labelWafAction(a.action) }}
            </span>
            <span class="font-mono text-[10px] text-slate-500" :title="a.action">{{ a.action }}</span>
            <span class="font-mono text-slate-400">{{ a.count }}</span>
          </li>
        </ul>
      </section>
      <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold text-white">Топ срабатываний по правилу</h3>
            <p class="mt-0.5 text-xs text-slate-500">Последние 10 за период · клик — все события по правилу</p>
          </div>
          <button
            type="button"
            class="shrink-0 rounded-lg border border-teal-600/40 bg-teal-950/40 px-3 py-1.5 text-xs font-medium text-teal-200 hover:bg-teal-900/50"
            @click="openAllWafEvents"
          >
            Далее →
          </button>
        </div>
        <ul class="mt-4 space-y-2 text-sm">
          <li v-if="!topWafRules.length" class="text-slate-500">Нет записей</li>
          <li
            v-for="(r, i) in topWafRules"
            :key="'r' + i"
            class="flex cursor-pointer flex-col gap-1 rounded-lg bg-slate-800/60 px-3 py-2 text-xs transition hover:bg-slate-700/80 sm:flex-row sm:items-center sm:justify-between"
            role="button"
            tabindex="0"
            @click="openRuleHits(r)"
            @keydown.enter="openRuleHits(r)"
          >
            <span class="min-w-0 flex-1">
              <span class="block truncate font-medium text-slate-200" :title="r.rule_name || r.rule_id">
                {{ r.rule_name || '—' }}
              </span>
              <span class="mt-0.5 block truncate font-mono text-[10px] text-slate-500" :title="r.rule_id">{{ r.rule_id }}</span>
            </span>
            <span class="text-teal-300/90">{{ labelWafAction(r.action) }}</span>
            <span class="font-mono text-slate-400">{{ r.count }}</span>
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
              <td colspan="2" class="py-6 text-center text-slate-500">
                Нет записей в журнале соединений за выбранный период (или данные ещё не подгрузились).
              </td>
            </tr>
            <tr
              v-for="(c, idx) in countryRows"
              :key="c.country_code ? c.country_code : 'unknown-' + idx"
              class="border-b border-slate-800/80"
            >
              <td class="py-2 pr-3 font-mono">{{ c.country_code ? c.country_code : '—' }}</td>
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

const { apiUrl, apiFetch } = useApi()
const { openWafEventsExplorer, openWafEventDetail } = useHashAppView()

type CountRow = { key: string; count: number }
type HostRow = { host: string; count: number }
type CountryRow = { country_code: string; count: number; lat: number; lon: number }
type WafAction = { action: string; count: number; last_hit_at?: string }
type WafRule = {
  rule_id: string
  rule_name?: string
  policy_id?: string
  policy_name?: string
  action: string
  count: number
  last_hit_at?: string
}
type RpsPoint = { bucket_start: string; bucket_seconds: number; count: number; rps: number }
type RpsOutcomeSeries = { outcome: string; points: RpsPoint[] }
type MalwareScanStats = { icap_checked: number; external_checked: number; blocked: number }

type Summary = {
  period_hours: number
  since: string
  by_host: HostRow[]
  hosts_total?: number
  by_method: CountRow[]
  by_protocol: CountRow[]
  by_outcome: CountRow[]
  by_country: CountryRow[]
  by_user_agent?: CountRow[]
  top_waf_actions: WafAction[]
  top_waf_rules: WafRule[]
  rps_series?: RpsPoint[]
  rps_by_outcome?: RpsOutcomeSeries[]
  waf_hits_series?: RpsPoint[]
  malware_scans?: MalwareScanStats
  rps_bucket_seconds?: number
  rps_bucket_interval?: string
}

const RANK_TOP = 10
const SERIES_VIS_LS_KEY = 'fence_dashboard_traffic_series_vis'
const OUTCOME_VIS_LS_KEY = 'fence_dashboard_outcome_vis'

const hours = ref(24)
const busy = ref(false)
const err = ref('')
const summary = ref<Summary | null>(null)
const hostsExpanded = ref(false)
const uaExpanded = ref(false)
const seriesVisible = ref<Record<string, boolean>>({})
const outcomeVisible = ref<Record<string, boolean>>({})

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
const elUA = ref<HTMLCanvasElement | null>(null)
const elRps = ref<HTMLCanvasElement | null>(null)
const elMap = ref<HTMLDivElement | null>(null)

let chartHost: ChartType | null = null
let chartMethod: ChartType | null = null
let chartProto: ChartType | null = null
let chartOutcome: ChartType | null = null
let chartUA: ChartType | null = null
let chartRps: ChartType | null = null
let mapInst: LeafMap | null = null
const markers: CircleMarker[] = []

let chartPrepared = false

function dashboardByCountry(s: Summary | null): CountryRow[] {
  if (!s) return []
  const x = s as Summary & { byCountry?: CountryRow[] }
  const rows = x.by_country ?? x.byCountry
  return Array.isArray(rows) ? rows : []
}

function dashboardByUserAgent(s: Summary | null): CountRow[] {
  if (!s) return []
  const x = s as Summary & { byUserAgent?: CountRow[] }
  const rows = x.by_user_agent ?? x.byUserAgent
  return Array.isArray(rows) ? rows : []
}

const countryRows = computed(() => dashboardByCountry(summary.value))

const topWafActions = computed(() => (summary.value?.top_waf_actions ?? []).slice(0, 10))
const topWafRules = computed(() => (summary.value?.top_waf_rules ?? []).slice(0, 10))

const malwareScans = computed((): MalwareScanStats => {
  const m = summary.value?.malware_scans
  return {
    icap_checked: Number(m?.icap_checked) || 0,
    external_checked: Number(m?.external_checked) || 0,
    blocked: Number(m?.blocked) || 0,
  }
})

function fmtCount(n: number) {
  return new Intl.NumberFormat('ru-RU').format(n)
}

const allHostRows = computed(() => summary.value?.by_host ?? [])
const visibleHostRows = computed(() => {
  const rows = allHostRows.value
  if (hostsExpanded.value) return rows
  return rows.slice(0, RANK_TOP)
})
const hostsHiddenCount = computed(() => Math.max(0, allHostRows.value.length - RANK_TOP))

const allUARows = computed(() => dashboardByUserAgent(summary.value))
const visibleUARows = computed(() => {
  const rows = allUARows.value
  if (uaExpanded.value) return rows
  return rows.slice(0, RANK_TOP)
})
const uaHiddenCount = computed(() => Math.max(0, allUARows.value.length - RANK_TOP))

function barChartHeight(rowCount: number) {
  const n = Math.max(rowCount, 1)
  return Math.min(Math.max(n * 28 + 48, 220), 960)
}

const hasTrafficChartData = computed(() => {
  const s = summary.value
  if (!s) return false
  return Boolean(
    s.rps_series?.length ||
      s.waf_hits_series?.length ||
      s.rps_by_outcome?.some((x) => x.points?.length),
  )
})

type SeriesMeta = { id: string; label: string; color: string }

const OUTCOME_SERIES_COLORS: Record<string, string> = {
  __total__: 'rgb(45, 212, 191)',
  __waf_hits__: 'rgb(167, 139, 250)',
  proxied: 'rgb(148, 163, 184)',
  waf_block: 'rgb(244, 63, 94)',
  redirect: 'rgb(56, 189, 248)',
  malware_block: 'rgb(251, 191, 36)',
  threat_feed_block: 'rgb(249, 115, 22)',
  threat_feed_log: 'rgb(253, 186, 116)',
  bot_rate_limit: 'rgb(236, 72, 153)',
  bot_score_block: 'rgb(217, 70, 239)',
  bot_score_log: 'rgb(192, 132, 252)',
  bot_challenge: 'rgb(168, 85, 247)',
  bot_asn_block: 'rgb(244, 114, 182)',
  bot_cidr_block: 'rgb(251, 113, 133)',
  geo_block: 'rgb(34, 197, 94)',
}

function seriesColor(id: string, fallbackIdx = 0) {
  if (OUTCOME_SERIES_COLORS[id]) return OUTCOME_SERIES_COLORS[id]
  const palette = ['rgb(94, 234, 212)', 'rgb(129, 140, 248)', 'rgb(251, 146, 60)', 'rgb(190, 242, 100)']
  return palette[fallbackIdx % palette.length]
}

function readJsonRecord(key: string): Record<string, boolean> {
  if (!import.meta.client) return {}
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Record<string, boolean>
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function writeJsonRecord(key: string, rec: Record<string, boolean>) {
  if (!import.meta.client) return
  try {
    localStorage.setItem(key, JSON.stringify(rec))
  } catch {
    /* ignore */
  }
}

function outcomeSeriesTotal(ser: RpsOutcomeSeries) {
  return ser.points.reduce((a, p) => a + (p.count || 0), 0)
}

function syncTrafficSeriesKeys(s: Summary) {
  const stored = readJsonRecord(SERIES_VIS_LS_KEY)
  const next: Record<string, boolean> = { ...seriesVisible.value }
  const ensure = (id: string, def: boolean) => {
    if (stored[id] !== undefined) next[id] = stored[id]
    else if (next[id] === undefined) next[id] = def
  }
  ensure('__total__', true)
  ensure('__waf_hits__', true)
  const outcomes = [...(s.rps_by_outcome || [])].sort((a, b) => {
    if (a.outcome === 'proxied') return 1
    if (b.outcome === 'proxied') return -1
    return outcomeSeriesTotal(b) - outcomeSeriesTotal(a)
  })
  for (const ser of outcomes) {
    ensure(ser.outcome, ser.outcome !== 'proxied')
  }
  seriesVisible.value = next
}

const trafficSeriesMeta = computed((): SeriesMeta[] => {
  const s = summary.value
  if (!s) return []
  const meta: SeriesMeta[] = [{ id: '__total__', label: 'RPS (всего)', color: seriesColor('__total__') }]
  if (s.waf_hits_series?.length) {
    meta.push({ id: '__waf_hits__', label: 'Срабатывания WAF', color: seriesColor('__waf_hits__') })
  }
  const outcomes = [...(s.rps_by_outcome || [])].sort((a, b) => {
    if (a.outcome === 'proxied') return 1
    if (b.outcome === 'proxied') return -1
    return outcomeSeriesTotal(b) - outcomeSeriesTotal(a)
  })
  let i = 0
  for (const ser of outcomes) {
    meta.push({
      id: ser.outcome,
      label: labelOutcome(ser.outcome),
      color: seriesColor(ser.outcome, i++),
    })
  }
  return meta
})

function toggleTrafficSeries(id: string) {
  const next = !(seriesVisible.value[id] !== false)
  seriesVisible.value = { ...seriesVisible.value, [id]: next }
  writeJsonRecord(SERIES_VIS_LS_KEY, seriesVisible.value)
  if (summary.value) void renderTrafficChart(summary.value)
}

const outcomeLegendItems = computed(() => {
  const rows = summary.value?.by_outcome ?? []
  return rows.map((r, i) => ({
    key: r.key,
    label: labelOutcome(r.key),
    color: seriesColor(r.key, i),
  }))
})

function syncOutcomeVisibleKeys(keys: string[]) {
  const stored = readJsonRecord(OUTCOME_VIS_LS_KEY)
  const next: Record<string, boolean> = { ...outcomeVisible.value }
  for (const k of keys) {
    if (stored[k] !== undefined) next[k] = stored[k]
    else if (next[k] === undefined) next[k] = true
  }
  outcomeVisible.value = next
}

function toggleOutcomeSlice(key: string) {
  const next = !(outcomeVisible.value[key] !== false)
  outcomeVisible.value = { ...outcomeVisible.value, [key]: next }
  writeJsonRecord(OUTCOME_VIS_LS_KEY, outcomeVisible.value)
  if (summary.value) void renderOutcomeChart(summary.value)
}

function openAllWafEvents() {
  openWafEventsExplorer({ hours: hours.value })
}

function openActionHits(a: WafAction) {
  if (!a.action) {
    openAllWafEvents()
    return
  }
  openWafEventsExplorer({ hours: hours.value, action: a.action })
}

function openRuleHits(r: WafRule) {
  if (!r.rule_id) {
    openAllWafEvents()
    return
  }
  openWafEventsExplorer({ hours: hours.value, rule_id: r.rule_id, action: r.action })
}

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
    allow: 'Разрешить',
    block: 'Блок WAF',
    log: 'Только лог',
    redirect: 'Редирект',
    replace: 'Замена',
    malware_block: 'Блок антивируса',
    waf_block: 'Блок WAF',
    threat_feed_block: 'Threat feed',
    threat_feed_log: 'Threat feed (лог)',
    bot_rate_limit: 'Rate limit бота',
    bot_score_block: 'Скоринг бота',
    bot_score_log: 'Скоринг бота (лог)',
    bot_challenge: 'Challenge бота',
    bot_asn_block: 'Блок ASN',
    bot_cidr_block: 'Блок CIDR',
    geo_block: 'GeoIP block',
  }
  return m[a] || a
}

function destroyCharts() {
  chartHost?.destroy()
  chartMethod?.destroy()
  chartProto?.destroy()
  chartOutcome?.destroy()
  chartUA?.destroy()
  chartRps?.destroy()
  chartHost = null
  chartMethod = null
  chartProto = null
  chartOutcome = null
  chartUA = null
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

async function buildBar(
  canvas: HTMLCanvasElement,
  labels: string[],
  data: number[],
  title: string,
  tooltipTitles?: string[],
) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  const tips =
    tooltipTitles && tooltipTitles.length === labels.length ? tooltipTitles : labels
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
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title(items) {
              const i = items[0]?.dataIndex ?? 0
              return tips[i] ?? ''
            },
            label(item) {
              return ` ${item.formattedValue}`
            },
          },
        },
      },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.12)' } },
        y: { ticks: { color: '#cbd5e1', maxRotation: 0 }, grid: { display: false } },
      },
    },
  })
}

type LineDatasetSpec = {
  label: string
  data: number[]
  borderColor: string
  backgroundColor?: string
  fill?: boolean
}

async function buildTrafficLineChart(canvas: HTMLCanvasElement, labels: string[], datasets: LineDatasetSpec[]) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  return new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: datasets.map((d) => ({
        label: d.label,
        data: d.data,
        fill: d.fill ?? false,
        backgroundColor: d.backgroundColor,
        borderColor: d.borderColor,
        borderWidth: 2,
        tension: 0.2,
        pointRadius: 0,
        pointHoverRadius: 4,
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label(ctx) {
              const v = typeof ctx.raw === 'number' ? ctx.raw : 0
              return ` ${ctx.dataset.label}: ${v.toFixed(3)} запр./с`
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

async function buildDoughnut(
  canvas: HTMLCanvasElement,
  labels: string[],
  data: number[],
  colors?: string[],
  showLegend = false,
) {
  await ensureChartLib()
  const { Chart } = await import('chart.js')
  const bg =
    colors && colors.length === labels.length
      ? colors
      : labels.map((_, i) => tealPalette(i, labels.length))
  return new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [
        {
          data,
          backgroundColor: bg,
          borderWidth: 1,
          borderColor: '#0f172a',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: showLegend
          ? { position: 'bottom', labels: { color: '#cbd5e1', boxWidth: 12 } }
          : { display: false },
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
    threat_feed_block: 'Threat feed',
    threat_feed_log: 'Threat feed (лог)',
    bot_rate_limit: 'Rate limit бота',
    bot_score_block: 'Скоринг бота',
    bot_score_log: 'Скоринг бота (лог)',
    bot_challenge: 'Challenge бота',
    bot_asn_block: 'Блок ASN',
    bot_cidr_block: 'Блок CIDR',
    geo_block: 'GeoIP block',
  }
  return m[o] || o
}

function rpsAlignedData(points: RpsPoint[] | undefined, bucketStarts: string[]): number[] {
  const m = new Map((points || []).map((p) => [p.bucket_start, p.rps]))
  return bucketStarts.map((b) => m.get(b) ?? 0)
}

function trafficBucketStarts(s: Summary): string[] {
  const fromTotal = s.rps_series?.map((p) => p.bucket_start) || []
  if (fromTotal.length) return fromTotal
  const fromWaf = s.waf_hits_series?.map((p) => p.bucket_start) || []
  if (fromWaf.length) return fromWaf
  const firstOutcome = s.rps_by_outcome?.find((x) => x.points?.length)
  return firstOutcome?.points.map((p) => p.bucket_start) || []
}

async function renderTrafficChart(s: Summary) {
  if (!import.meta.client) return
  syncTrafficSeriesKeys(s)
  chartRps?.destroy()
  chartRps = null
  await nextTick()
  const bucketStarts = trafficBucketStarts(s)
  if (!elRps.value || !bucketStarts.length) return

  const datasets: LineDatasetSpec[] = []
  if (seriesVisible.value.__total__ !== false && s.rps_series?.length) {
    const c = seriesColor('__total__')
    datasets.push({
      label: 'RPS (всего)',
      data: rpsAlignedData(s.rps_series, bucketStarts),
      borderColor: c,
      fill: true,
      backgroundColor: 'rgba(45, 212, 191, 0.1)',
    })
  }
  if (seriesVisible.value.__waf_hits__ !== false && s.waf_hits_series?.length) {
    const c = seriesColor('__waf_hits__')
    datasets.push({
      label: 'Срабатывания WAF',
      data: rpsAlignedData(s.waf_hits_series, bucketStarts),
      borderColor: c,
    })
  }
  const outcomes = [...(s.rps_by_outcome || [])].sort((a, b) => {
    if (a.outcome === 'proxied') return 1
    if (b.outcome === 'proxied') return -1
    return outcomeSeriesTotal(b) - outcomeSeriesTotal(a)
  })
  let colorIdx = 0
  for (const ser of outcomes) {
    if (seriesVisible.value[ser.outcome] === false) continue
    const c = seriesColor(ser.outcome, colorIdx++)
    datasets.push({
      label: labelOutcome(ser.outcome),
      data: rpsAlignedData(ser.points, bucketStarts),
      borderColor: c,
    })
  }
  if (!datasets.length) return

  const labels = bucketStarts.map((b) => fmtBucketLabel(b))
  chartRps = await buildTrafficLineChart(elRps.value, labels, datasets)
}

async function renderHostChart(s: Summary) {
  if (!import.meta.client) return
  chartHost?.destroy()
  chartHost = null
  await nextTick()
  const rows = visibleHostRows.value
  if (!elHost.value || !rows.length) return
  chartHost = await buildBar(
    elHost.value,
    rows.map((x) => x.host || '—'),
    rows.map((x) => Number(x.count) || 0),
    'Запросы',
    rows.map((x) => x.host || '—'),
  )
}

async function renderUAChart(s: Summary) {
  if (!import.meta.client) return
  chartUA?.destroy()
  chartUA = null
  await nextTick()
  const rows = visibleUARows.value
  if (!elUA.value || !rows.length) return
  const full = rows.map((x) => (x.key || '').trim() || '—')
  const labels = full.map((t) => (t.length > 56 ? `${t.slice(0, 56)}…` : t))
  chartUA = await buildBar(elUA.value, labels, rows.map((x) => Number(x.count) || 0), 'Запросы', full)
}

async function renderOutcomeChart(s: Summary) {
  if (!import.meta.client) return
  const rows = s.by_outcome || []
  syncOutcomeVisibleKeys(rows.map((x) => x.key))
  chartOutcome?.destroy()
  chartOutcome = null
  await nextTick()
  const visible = rows.filter((x) => outcomeVisible.value[x.key] !== false)
  if (!elOutcome.value || !visible.length) return
  chartOutcome = await buildDoughnut(
    elOutcome.value,
    visible.map((x) => labelOutcome(x.key)),
    visible.map((x) => x.count),
    visible.map((x, i) => seriesColor(x.key, i)),
  )
}

async function renderCharts(s: Summary) {
  if (!import.meta.client) return
  destroyCharts()
  await nextTick()
  if (elMethod.value && s.by_method?.length) {
    chartMethod = await buildDoughnut(
      elMethod.value,
      s.by_method.map((x) => x.key || '—'),
      s.by_method.map((x) => x.count),
      undefined,
      true,
    )
  }
  if (elProto.value && s.by_protocol?.length) {
    chartProto = await buildDoughnut(
      elProto.value,
      s.by_protocol.map((x) => (x.key === 'https' ? 'HTTPS' : x.key === 'http' ? 'HTTP' : x.key || '—')),
      s.by_protocol.map((x) => x.count),
      undefined,
      true,
    )
  }
  await renderOutcomeChart(s)
  await renderHostChart(s)
  await renderUAChart(s)
}

async function renderMap(rows: CountryRow[]) {
  if (!import.meta.client || !elMap.value) return
  await import('leaflet/dist/leaflet.css')
  const L = (await import('leaflet')).default

  for (const m of markers) {
    try {
      m.remove()
    } catch {
      /* ignore */
    }
  }
  markers.length = 0
  try {
    mapInst?.remove()
  } catch {
    /* ignore */
  }
  mapInst = null

  // Leaflet needs an empty container. A previous "no data" pass sets innerHTML — clear before L.map.
  elMap.value.innerHTML = ''

  const pts = rows
    .map((r) => ({
      ...r,
      lat: Number(r.lat),
      lon: Number(r.lon),
      count: Number(r.count) || 0,
    }))
    .filter((r) => Number.isFinite(r.lat) && Number.isFinite(r.lon) && (r.lat !== 0 || r.lon !== 0))

  if (!pts.length) {
    elMap.value.innerHTML =
      '<div class="flex h-full items-center justify-center px-4 text-center text-sm text-slate-500">Нет точек на карте: в логах нет известного кода страны. Установите базу GeoIP в разделе <span class="font-mono text-slate-400">Антивирус / Malware → GeoIP</span> (загрузка файла или скачивание по HTTPS), либо задайте <span class="font-mono text-slate-400">GEOIP_MMDB_PATH</span> на шлюзе / общий том в compose. Либо пробросьте <span class="font-mono text-slate-400">CF-IPCountry</span> с Cloudflare. Редкие коды без центроида в справочнике не попадут на карту.</div>'
    return
  }

  const map = L.map(elMap.value, { scrollWheelZoom: false, worldCopyJump: true }).setView([20, 0], 2)
  // Leaflet по умолчанию добавляет SVG-флаг в префикс атрибуции; оставляем только ссылку на leafletjs.com
  map.attributionControl.setPrefix(
    '<a href="https://leafletjs.com" title="A JavaScript library for interactive maps">Leaflet</a>',
  )
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

  await nextTick()
  requestAnimationFrame(() => {
    map.invalidateSize()
    requestAnimationFrame(() => map.invalidateSize())
  })
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const q = new URLSearchParams({ hours: String(hours.value) })
    const data = await apiFetch<Summary>(`${apiUrl('/dashboard/summary')}?${q}`)
    const byCountry = dashboardByCountry(data)
    const byUserAgent = dashboardByUserAgent(data)
    summary.value = { ...data, by_country: byCountry, by_user_agent: byUserAgent }
    await renderCharts(summary.value)
    await renderTrafficChart(summary.value)
    await nextTick()
    await renderMap(byCountry)
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

watch(hostsExpanded, () => {
  if (summary.value) void renderHostChart(summary.value)
})

watch(uaExpanded, () => {
  if (summary.value) void renderUAChart(summary.value)
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
  try {
    mapInst?.remove()
  } catch {
    /* ignore */
  }
  mapInst = null
  markers.length = 0
})
</script>
