<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <div class="flex flex-wrap gap-2">
      <button
        type="button"
        class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
        :disabled="busy"
        @click="load"
      >
        Обновить
      </button>
      <button
        type="button"
        class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
        :disabled="busy"
        @click="save"
      >
        Сохранить
      </button>
      <button
        type="button"
        class="rounded-lg border border-teal-700 bg-slate-900 px-4 py-2 text-sm text-teal-100 hover:bg-slate-800"
        :disabled="busy"
        @click="syncNow"
      >
        Синхронизировать сейчас
      </button>
    </div>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Q-feed (угрозы по IP)</h2>
      <p class="mt-1 text-sm text-slate-400">
        Внешний список IP/CIDR после фильтра по полю <span class="font-mono text-slate-300">source</span>. Шлюз проверяет клиентский IP
        <strong class="text-slate-300">до</strong> чтения тела запроса. Индикаторы подхватываются по событию Redis после синка (policy-api или
        интервал опроса).
      </p>

      <div v-if="feedStatus" class="mt-4 grid gap-3 text-sm sm:grid-cols-2">
        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Индикаторов в БД</span>
          <span class="ml-2 font-mono text-teal-200/90">{{ feedStatus.indicator_count }}</span>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Строк в последнем импорте</span>
          <span class="ml-2 font-mono text-slate-300">{{ feedStatus.rows_last_ingested }}</span>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3 sm:col-span-2">
          <span class="text-slate-500">Последний успех</span>
          <span class="ml-2 font-mono text-xs text-slate-300">{{ fmtTs(feedStatus.last_success_at) }}</span>
          <span class="mx-3 text-slate-600">|</span>
          <span class="text-slate-500">Последняя попытка</span>
          <span class="ml-2 font-mono text-xs text-slate-300">{{ fmtTs(feedStatus.last_attempt_at) }}</span>
        </div>
        <p v-if="feedStatus.last_error" class="sm:col-span-2 rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-xs text-amber-100">
          {{ feedStatus.last_error }}
        </p>
      </div>

      <div class="mt-6 grid gap-4 sm:grid-cols-2">
        <label class="flex items-center gap-2 text-sm text-slate-300 sm:col-span-2">
          <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
          Включить фид на шлюзе
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.block" type="checkbox" class="rounded border-slate-600" />
          Блокировать (403)
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.log_hits" type="checkbox" class="rounded border-slate-600" />
          Писать попадания в WAF-журнал
        </label>

        <input
          v-model="cfg.feed_url"
          placeholder="https://feed.example/threat-list.csv"
          class="sm:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
        />

        <input
          v-model.number="cfg.poll_interval_sec"
          type="number"
          min="60"
          placeholder="Интервал опроса, сек"
          class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
        />
        <input
          v-model.number="cfg.http_timeout_sec"
          type="number"
          min="5"
          placeholder="Таймаут HTTP, сек"
          class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
        />

        <label class="text-sm text-slate-400 sm:col-span-2">
          Формат
          <select v-model="cfg.format" class="ml-2 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200">
            <option value="auto">auto</option>
            <option value="csv">csv</option>
            <option value="plain">plain</option>
            <option value="ndjson">ndjson</option>
          </select>
        </label>

        <input v-model="cfg.csv_indicator_column" placeholder="CSV: колонка IP (indicator)" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        <input v-model="cfg.csv_source_column" placeholder="CSV: колонка source (фильтр)" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />

        <label class="text-sm text-slate-400 sm:col-span-2">
          Разрешённые значения source (по строке; пусто = все)
          <textarea v-model="sourcesStr" rows="4" class="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200" />
        </label>

        <input v-model="cfg.api_key_header" placeholder="Заголовок ключа API" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono" />
        <input
          v-model="cfg.api_key"
          type="password"
          autocomplete="new-password"
          :placeholder="apiKeySet ? 'Ключ задан (оставьте пустым или *** чтобы не менять)' : 'API key (если нужен)'"
          class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
        />
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl } = useApi()

type ThreatFeedCfg = {
  enabled: boolean
  block: boolean
  log_hits: boolean
  feed_url: string
  poll_interval_sec: number
  http_timeout_sec: number
  sources: string[]
  format: string
  csv_indicator_column: string
  csv_source_column: string
  api_key: string
  api_key_header: string
}

type ThreatFeedResp = ThreatFeedCfg & { api_key_set?: boolean }

type ThreatFeedStatus = {
  enabled: boolean
  block: boolean
  last_attempt_at?: string
  last_success_at?: string
  last_error?: string
  rows_last_ingested: number
  indicator_count: number
}

function defaultCfg(): ThreatFeedCfg {
  return {
    enabled: false,
    block: true,
    log_hits: true,
    feed_url: '',
    poll_interval_sec: 3600,
    http_timeout_sec: 120,
    sources: [],
    format: 'auto',
    csv_indicator_column: '',
    csv_source_column: '',
    api_key: '',
    api_key_header: 'Authorization',
  }
}

const cfg = ref<ThreatFeedCfg>(defaultCfg())
const sourcesStr = ref('')
const apiKeySet = ref(false)
const feedStatus = ref<ThreatFeedStatus | null>(null)
const err = ref('')
const ok = ref('')
const busy = ref(false)

function fmtTs(s?: string) {
  if (!s) return '—'
  try {
    return new Date(s).toLocaleString()
  } catch {
    return s
  }
}

function flashErr(e: unknown) {
  ok.value = ''
  const fe = e as FetchError<{ error?: string }>
  err.value = fe?.data?.error || fe?.message || String(e)
}

function flashOk(msg: string) {
  err.value = ''
  ok.value = msg
  setTimeout(() => {
    ok.value = ''
  }, 4000)
}

async function loadStatus() {
  feedStatus.value = await $fetch<ThreatFeedStatus>(apiUrl('/settings/threat-feed/status'))
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const data = await $fetch<ThreatFeedResp>(apiUrl('/settings/threat-feed'))
    apiKeySet.value = !!data.api_key_set
    const { api_key_set: _k, ...rest } = data
    cfg.value = { ...defaultCfg(), ...rest }
    sourcesStr.value = (cfg.value.sources || []).join('\n')
    await loadStatus().catch(flashErr)
    flashOk('Загружено')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function save() {
  busy.value = true
  err.value = ''
  try {
    const sources = sourcesStr.value
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)
    const body = { ...cfg.value, sources }
    await $fetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body })
    await load()
    flashOk('Сохранено')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function syncNow() {
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl('/settings/threat-feed/sync'), { method: 'POST' })
    await loadStatus().catch(flashErr)
    flashOk('Синхронизация запущена')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  load()
})
</script>
