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
        Сохранить настройки
      </button>
    </div>

    <section class="rounded-2xl border border-teal-900/50 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Загрузка списка IP</h2>
      <p class="mt-1 text-sm text-slate-400">
        Текстовый файл <span class="font-mono text-slate-300">.txt</span>: один IPv4, IPv6 или CIDR на строку.
        Пустые строки и строки с <span class="font-mono text-slate-300">#</span> в начале игнорируются. Список в БД
        <strong class="text-slate-300">полностью заменяется</strong> содержимым файла.
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
        </div>
        <p
          v-if="feedStatus.last_error"
          class="sm:col-span-2 rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-xs text-amber-100"
        >
          {{ feedStatus.last_error }}
        </p>
      </div>

      <div class="mt-6 flex flex-wrap items-end gap-4">
        <label class="block text-sm text-slate-400">
          Файл
          <input
            ref="fileInput"
            type="file"
            accept=".txt,text/plain"
            class="mt-2 block max-w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-teal-800 file:px-4 file:py-2 file:text-sm file:font-medium file:text-white hover:file:bg-teal-700"
            :disabled="busy"
            @change="onFilePicked"
          />
        </label>
        <button
          type="button"
          class="rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
          :disabled="busy || !pickedFile"
          @click="upload"
        >
          Загрузить и применить
        </button>
        <p v-if="pickedFile" class="text-xs text-slate-500">{{ pickedFile.name }} ({{ fmtSize(pickedFile.size) }})</p>
      </div>

      <pre class="mt-4 rounded-lg border border-slate-800 bg-slate-950/80 p-3 font-mono text-xs text-slate-500">192.0.2.1
203.0.113.0/24
# комментарий
2001:db8::1</pre>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Шлюз</h2>
      <p class="mt-1 text-sm text-slate-400">
        После загрузки включите фид — шлюз проверяет клиентский IP до чтения тела запроса.
      </p>

      <div class="mt-4 grid gap-4 sm:grid-cols-2">
        <label class="flex items-center gap-2 text-sm text-slate-300 sm:col-span-2">
          <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
          Включить блоклист на шлюзе
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.block" type="checkbox" class="rounded border-slate-600" />
          Блокировать (403)
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.log_hits" type="checkbox" class="rounded border-slate-600" />
          Писать попадания в WAF-журнал
        </label>
      </div>
    </section>

    <details class="rounded-2xl border border-white/10 bg-slate-900/30">
      <summary class="cursor-pointer px-6 py-4 text-sm font-medium text-slate-300 hover:text-white">
        Синхронизация по URL (Q-Feeds и др.) — опционально
      </summary>
      <div class="border-t border-white/5 px-6 pb-6 pt-2">
        <div class="flex flex-wrap gap-2 pb-4">
          <button
            type="button"
            class="rounded-lg border border-teal-700 bg-slate-900 px-4 py-2 text-sm text-teal-100 hover:bg-slate-800"
            :disabled="busy"
            @click="syncNow"
          >
            Синхронизировать сейчас
          </button>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <input
            v-model="cfg.feed_url"
            placeholder="https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=…"
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
              <option value="plain">plain</option>
              <option value="csv">csv</option>
              <option value="ndjson">ndjson</option>
            </select>
          </label>
          <input
            v-model="cfg.api_key"
            type="password"
            autocomplete="new-password"
            :placeholder="apiKeySet ? 'Ключ задан (пусто = не менять)' : 'API key'"
            class="sm:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
          />
        </div>
      </div>
    </details>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

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

type UploadResp = { ok: boolean; rows_ingested: number }

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
const apiKeySet = ref(false)
const feedStatus = ref<ThreatFeedStatus | null>(null)
const err = ref('')
const ok = ref('')
const busy = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const pickedFile = ref<File | null>(null)

function fmtTs(s?: string) {
  if (!s) return '—'
  try {
    return new Date(s).toLocaleString()
  } catch {
    return s
  }
}

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`
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
  }, 5000)
}

function currentSettingsBody() {
  return { ...cfg.value, sources: [] as string[] }
}

function onFilePicked(ev: Event) {
  const input = ev.target as HTMLInputElement
  pickedFile.value = input.files?.[0] ?? null
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
    await loadStatus().catch(flashErr)
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
    await apiFetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body: currentSettingsBody() })
    await load()
    flashOk('Настройки сохранены')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function upload() {
  const file = pickedFile.value
  if (!file) return
  busy.value = true
  err.value = ''
  try {
    const fd = new FormData()
    fd.append('file', file, file.name)
    const res = await $fetch<UploadResp>(apiUrl('/settings/threat-feed/upload'), {
      method: 'POST',
      body: fd,
    })
    pickedFile.value = null
    if (fileInput.value) fileInput.value.value = ''
    await loadStatus()
    flashOk(`Загружено ${res.rows_ingested} индикаторов`)
  } catch (e) {
    flashErr(e)
    await loadStatus().catch(() => {})
  } finally {
    busy.value = false
  }
}

async function syncNow() {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body: currentSettingsBody() })
    await apiFetch(apiUrl('/settings/threat-feed/sync'), { method: 'POST' })
    await load()
    flashOk('Синхронизация по URL выполнена')
  } catch (e) {
    flashErr(e)
    await loadStatus().catch(() => {})
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  load()
})
</script>
