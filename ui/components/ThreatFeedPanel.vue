<template>
  <motion.div class="space-y-6" :initial="{ opacity: 0 }" :animate="{ opacity: 1 }">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <motion.div class="flex flex-wrap gap-2" :initial="{ opacity: 0 }" :animate="{ opacity: 1 }">
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
    </motion.div>

    <motion.section
      class="rounded-2xl border border-orange-900/40 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
      :initial="{ opacity: 0, y: 8 }"
      :animate="{ opacity: 1, y: 0 }"
    >
      <h2 class="text-lg font-semibold text-white">ThreatFox (abuse.ch)</h2>
      <p class="mt-1 text-sm text-slate-400">
        Источник IOC: полный CSV-экспорт (~6 мес.) и инкремент через
        <a href="https://threatfox.abuse.ch/api/" target="_blank" rel="noopener" class="text-teal-400 hover:underline">Community API</a>.
        Auth-Key — на
        <a href="https://auth.abuse.ch/" target="_blank" rel="noopener" class="text-teal-400 hover:underline">auth.abuse.ch</a>.
        Авто-синхронизация API — <strong class="text-slate-300">2 раза в сутки</strong> (добавляет новые IP).
        При пустом блоклисте после включения выполняется полная загрузка автоматически.
      </p>
      <p class="mt-2 text-xs text-slate-500">
        В блоклист попадают только IP/CIDR (типы <span class="font-mono">ip</span>, <span class="font-mono">ip:port</span>).
        Ложные срабатывания — в разделе <strong class="text-slate-400">Настройки → Исключения</strong> или из карточки события WAF.
      </p>

      <div class="mt-4 flex flex-wrap gap-2">
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="useThreatFox" type="checkbox" class="rounded border-slate-600" @change="onProviderChange" />
          Использовать ThreatFox
        </label>
      </div>

      <div v-if="useThreatFox" class="mt-4 space-y-4">
        <label class="block text-xs text-slate-500">
          Auth-Key (токен)
          <input
            v-model="cfg.api_key"
            type="password"
            autocomplete="new-password"
            :placeholder="apiKeySet ? 'Оставьте пустым, чтобы не менять' : 'Вставьте Auth-Key с auth.abuse.ch'"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
          />
        </label>
        <label class="block text-xs text-slate-500">
          Таймаут HTTP, сек (полный экспорт может занять несколько минут)
          <input
            v-model.number="cfg.http_timeout_sec"
            type="number"
            min="60"
            max="3600"
            class="mt-1 w-full max-w-xs rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          />
        </label>
        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            class="rounded-lg bg-orange-700 px-4 py-2 text-sm font-medium text-white hover:bg-orange-600 disabled:opacity-50"
            :disabled="busy || (!apiKeySet && !cfg.api_key)"
            @click="fullThreatFox"
          >
            Полное обновление (замена списка)
          </button>
          <button
            type="button"
            class="rounded-lg border border-teal-700 bg-slate-900 px-4 py-2 text-sm text-teal-100 hover:bg-slate-800 disabled:opacity-50"
            :disabled="busy || (!apiKeySet && !cfg.api_key)"
            @click="syncIncremental"
          >
            Синхронизировать сейчас (API, 1 день)
          </button>
        </div>
        <p v-if="feedStatus?.threatfox_ready" class="text-xs text-emerald-400/90">Auth-Key задан · провайдер threatfox</p>
      </div>
    </motion.section>

    <motion.section
      v-if="feedStatus"
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6"
      :initial="{ opacity: 0 }"
      :animate="{ opacity: 1 }"
    >
      <div class="grid gap-3 text-sm sm:grid-cols-2">
        <motion.div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Индикаторов в БД</span>
          <span class="ml-2 font-mono text-teal-200/90">{{ feedStatus.indicator_count }}</span>
        </motion.div>
        <motion.div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Строк в последней синхронизации</span>
          <span class="ml-2 font-mono text-slate-300">{{ feedStatus.rows_last_ingested }}</span>
        </motion.div>
        <motion.div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Авто-синхронизаций сегодня (UTC)</span>
          <span class="ml-2 font-mono text-slate-300">{{ feedStatus.auto_syncs_today ?? 0 }} / {{ feedStatus.auto_sync_limit ?? 2 }}</span>
        </motion.div>
        <motion.div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
          <span class="text-slate-500">Следующая авто-синхронизация</span>
          <span class="ml-2 font-mono text-xs text-slate-300">{{ fmtTs(feedStatus.next_auto_sync_at) }}</span>
        </motion.div>
        <motion.div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3 sm:col-span-2">
          <span class="text-slate-500">Последний успех</span>
          <span class="ml-2 font-mono text-xs text-slate-300">{{ fmtTs(feedStatus.last_success_at) }}</span>
        </motion.div>
        <p
          v-if="feedStatus.last_error"
          class="sm:col-span-2 rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-xs text-amber-100"
        >
          {{ feedStatus.last_error }}
        </p>
      </div>
    </motion.section>

    <motion.section
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
      :initial="{ opacity: 0, y: 8 }"
      :animate="{ opacity: 1, y: 0 }"
    >
      <h2 class="text-lg font-semibold text-white">Шлюз WAF</h2>
      <p class="mt-1 text-sm text-slate-400">
        Проверка клиентского IP до чтения тела запроса. Исключения (обход блоклиста) — глобальные IP/CIDR в «Исключения».
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
    </motion.section>

    <motion.section
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6"
      :initial="{ opacity: 0 }"
      :animate="{ opacity: 1 }"
    >
      <h2 class="text-lg font-semibold text-white">Ручная загрузка .txt</h2>
      <p class="mt-1 text-sm text-slate-400">
        Один IPv4, IPv6 или CIDR на строку. Список в БД <strong class="text-slate-300">полностью заменяется</strong>.
      </p>
      <motion.div class="mt-6 flex flex-wrap items-end gap-4">
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
      </motion.div>
    </motion.section>

    <details class="rounded-2xl border border-white/10 bg-slate-900/30">
      <summary class="cursor-pointer px-6 py-4 text-sm font-medium text-slate-300 hover:text-white">
        Синхронизация по URL (Q-Feeds и др.)
      </summary>
      <div class="border-t border-white/5 px-6 pb-6 pt-2">
        <p class="pb-3 text-xs text-slate-500">
          Альтернатива ThreatFox. Авто-загрузка — не чаще 2 раз в сутки. Отключите ThreatFox выше, чтобы использовать URL.
        </p>
        <div class="grid gap-4 sm:grid-cols-2">
          <input
            v-model="cfg.feed_url"
            placeholder="https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=…"
            class="sm:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
            :disabled="useThreatFox"
          />
          <label class="text-sm text-slate-400">
            Интервал авто-синхронизации (сек, мин. 43200)
            <input
              v-model.number="cfg.poll_interval_sec"
              type="number"
              min="43200"
              step="3600"
              class="mt-1 block w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            />
          </label>
          <label class="text-sm text-slate-400 sm:col-span-2">
            Формат
            <select v-model="cfg.format" class="ml-2 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200">
              <option value="auto">auto</option>
              <option value="plain">plain</option>
              <option value="csv">csv</option>
              <option value="ndjson">ndjson</option>
            </select>
          </label>
        </div>
        <button
          type="button"
          class="mt-4 rounded-lg border border-teal-700 bg-slate-900 px-4 py-2 text-sm text-teal-100 hover:bg-slate-800"
          :disabled="busy || useThreatFox"
          @click="syncUrl"
        >
          Синхронизировать URL вручную
        </button>
      </div>
    </details>
  </motion.div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

type ThreatFeedCfg = {
  enabled: boolean
  block: boolean
  log_hits: boolean
  provider: string
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
  provider?: string
  threatfox_ready?: boolean
  last_attempt_at?: string
  last_success_at?: string
  last_error?: string
  rows_last_ingested: number
  indicator_count: number
  auto_syncs_today?: number
  auto_sync_limit?: number
  next_auto_sync_at?: string
}

type UploadResp = { ok: boolean; rows_ingested: number }

function defaultCfg(): ThreatFeedCfg {
  return {
    enabled: false,
    block: true,
    log_hits: true,
    provider: 'threatfox',
    feed_url: '',
    poll_interval_sec: 43200,
    http_timeout_sec: 600,
    sources: [],
    format: 'auto',
    csv_indicator_column: '',
    csv_source_column: '',
    api_key: '',
    api_key_header: 'Auth-Key',
  }
}

const cfg = ref<ThreatFeedCfg>(defaultCfg())
const useThreatFox = ref(true)
const apiKeySet = ref(false)
const feedStatus = ref<ThreatFeedStatus | null>(null)
const err = ref('')
const ok = ref('')
const busy = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const pickedFile = ref<File | null>(null)

function onProviderChange() {
  cfg.value.provider = useThreatFox.value ? 'threatfox' : 'url'
  if (useThreatFox.value) {
    cfg.value.api_key_header = 'Auth-Key'
  }
}

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
  return {
    ...cfg.value,
    provider: useThreatFox.value ? 'threatfox' : 'url',
    api_key_header: useThreatFox.value ? 'Auth-Key' : cfg.value.api_key_header || 'Authorization',
    sources: [] as string[],
  }
}

function onFilePicked(ev: Event) {
  const input = ev.target as HTMLInputElement
  pickedFile.value = input.files?.[0] ?? null
}

async function loadStatus() {
  feedStatus.value = await apiFetch<ThreatFeedStatus>(apiUrl('/settings/threat-feed/status'))
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const data = await apiFetch<ThreatFeedResp>(apiUrl('/settings/threat-feed'))
    apiKeySet.value = !!data.api_key_set
    const { api_key_set: _k, ...rest } = data
    cfg.value = { ...defaultCfg(), ...rest }
    useThreatFox.value = !rest.provider || rest.provider === 'threatfox'
    if (useThreatFox.value) {
      cfg.value.provider = 'threatfox'
      cfg.value.api_key_header = 'Auth-Key'
    }
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
    const res = await apiFetch<UploadResp>(apiUrl('/settings/threat-feed/upload'), {
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

async function syncIncremental() {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body: currentSettingsBody() })
    await apiFetch(apiUrl('/settings/threat-feed/sync'), { method: 'POST' })
    await load()
    flashOk('Инкрементальная синхронизация ThreatFox выполнена')
  } catch (e) {
    flashErr(e)
    await loadStatus().catch(() => {})
  } finally {
    busy.value = false
  }
}

async function fullThreatFox() {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body: currentSettingsBody() })
    await apiFetch(apiUrl('/settings/threat-feed/threatfox/full'), { method: 'POST' })
    await load()
    flashOk('Полное обновление ThreatFox выполнено')
  } catch (e) {
    flashErr(e)
    await loadStatus().catch(() => {})
  } finally {
    busy.value = false
  }
}

async function syncUrl() {
  busy.value = true
  err.value = ''
  try {
    const body = { ...currentSettingsBody(), provider: 'url' as const }
    await apiFetch(apiUrl('/settings/threat-feed'), { method: 'PUT', body })
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
