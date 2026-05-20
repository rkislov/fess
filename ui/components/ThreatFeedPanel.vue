<template>
  <motion.div class="space-y-5" :initial="{ opacity: 0 }" :animate="{ opacity: 1 }">
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
        class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        :disabled="busy"
        @click="save"
      >
        Сохранить настройки
      </button>
    </div>

    <!-- ThreatFox -->
    <section class="rounded-2xl border border-orange-900/35 bg-slate-900/50 p-5 sm:p-6">
      <h2 class="text-base font-semibold text-white">ThreatFox (abuse.ch)</h2>
      <p class="mt-1.5 text-sm leading-relaxed text-slate-400">
        Синхронизируются IP/CIDR и хэши файлов (<span class="font-mono text-slate-500">md5_hash</span>,
        <span class="font-mono text-slate-500">sha256_hash</span>). Хэши проверяются в цепочке антивируса до ICAP/HTTP-сканера.
        Auth-Key —
        <a href="https://auth.abuse.ch/" target="_blank" rel="noopener" class="text-teal-400 hover:underline">auth.abuse.ch</a>.
        Авто-синхронизация — <strong class="font-normal text-slate-300">2 раза в сутки</strong>.
      </p>

      <label class="mt-4 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="useThreatFox" type="checkbox" class="rounded border-slate-600" @change="onProviderChange" />
        Использовать ThreatFox
      </label>

      <div v-if="useThreatFox" class="mt-4 space-y-4 border-t border-white/5 pt-4">
        <label class="block text-xs text-slate-500">
          Auth-Key (токен)
          <input
            v-model="cfg.api_key"
            type="password"
            autocomplete="new-password"
            :placeholder="apiKeySet ? 'Оставьте пустым, чтобы не менять' : 'Вставьте Auth-Key'"
            class="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
          />
        </label>
        <label class="block max-w-xs text-xs text-slate-500">
          Таймаут HTTP, сек
          <input
            v-model.number="cfg.http_timeout_sec"
            type="number"
            min="60"
            max="3600"
            class="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          />
        </label>

        <motion.div class="flex flex-wrap gap-2" :initial="{ opacity: 0 }" :animate="{ opacity: 1 }">
          <button
            type="button"
            class="rounded-lg bg-orange-700 px-4 py-2 text-sm font-medium text-white hover:bg-orange-600 disabled:opacity-50"
            :disabled="busy || (!apiKeySet && !cfg.api_key)"
            @click="fullThreatFox"
          >
            Полное обновление
          </button>
          <button
            type="button"
            class="rounded-lg border border-teal-700/80 bg-slate-950 px-4 py-2 text-sm text-teal-100 hover:bg-slate-900 disabled:opacity-50"
            :disabled="busy || (!apiKeySet && !cfg.api_key)"
            @click="syncIncremental"
          >
            Синхронизировать сейчас
          </button>
        </motion.div>

        <p
          v-if="feedStatus?.threatfox_ready"
          class="inline-flex items-center gap-1.5 rounded-full border border-emerald-800/60 bg-emerald-950/40 px-2.5 py-1 text-xs text-emerald-300/95"
        >
          <span class="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
          Auth-Key задан
        </p>
      </div>
    </section>

    <!-- Status -->
    <section v-if="feedStatus" class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 sm:p-6">
      <h3 class="text-sm font-semibold text-slate-200">Состояние блоклиста</h3>
      <dl class="mt-4 grid gap-3 sm:grid-cols-2">
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
          <dt class="text-xs text-slate-500">IP/CIDR в БД</dt>
          <dd class="mt-1 font-mono text-xl tabular-nums text-teal-200">{{ feedStatus.indicator_count }}</dd>
        </motion.div>
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
          <dt class="text-xs text-slate-500">Хэшей файлов в БД</dt>
          <dd class="mt-1 font-mono text-xl tabular-nums text-orange-200">{{ feedStatus.file_hash_count ?? 0 }}</dd>
        </motion.div>
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
          <dt class="text-xs text-slate-500">Строк в последней синхронизации</dt>
          <dd class="mt-1 font-mono text-xl tabular-nums text-slate-200">{{ feedStatus.rows_last_ingested }}</dd>
        </motion.div>
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
          <dt class="text-xs text-slate-500">Авто-синхронизаций сегодня (UTC)</dt>
          <dd class="mt-1 font-mono text-xl tabular-nums text-slate-200">
            {{ feedStatus.auto_syncs_today ?? 0 }} / {{ feedStatus.auto_sync_limit ?? 2 }}
          </dd>
        </motion.div>
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3">
          <dt class="text-xs text-slate-500">Следующая авто-синхронизация</dt>
          <dd class="mt-1 text-sm leading-snug text-slate-300">{{ fmtTs(feedStatus.next_auto_sync_at) }}</dd>
        </motion.div>
        <motion.div class="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3 sm:col-span-2">
          <dt class="text-xs text-slate-500">Последний успех</dt>
          <dd class="mt-1 text-sm text-slate-300">{{ fmtTs(feedStatus.last_success_at) }}</dd>
        </motion.div>
      </dl>
      <p
        v-if="feedStatus.last_error"
        class="mt-3 rounded-lg border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-100"
      >
        {{ feedStatus.last_error }}
      </p>
    </section>

    <!-- Gateway -->
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 sm:p-6">
      <h2 class="text-base font-semibold text-white">Шлюз WAF</h2>
      <p class="mt-1 text-sm text-slate-400">
        Проверка IP до чтения тела. Обход — <strong class="font-normal text-slate-300">Настройки → Исключения</strong>.
      </p>
      <motion.div class="mt-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
          Включить блоклист
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.block" type="checkbox" class="rounded border-slate-600" />
          Блокировать (403)
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.log_hits" type="checkbox" class="rounded border-slate-600" />
          Журнал WAF
        </label>
      </motion.div>
    </section>

    <!-- Manual upload -->
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 sm:p-6">
      <h2 class="text-base font-semibold text-white">Ручная загрузка .txt</h2>
      <p class="mt-1 text-sm text-slate-400">Один IP или CIDR на строку. Список в БД полностью заменяется.</p>
      <motion.div class="mt-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end">
        <label class="block min-w-0 flex-1 text-sm text-slate-400">
          Файл
          <input
            ref="fileInput"
            type="file"
            accept=".txt,text/plain"
            class="mt-2 block w-full max-w-md text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-teal-800 file:px-4 file:py-2 file:text-sm file:text-white hover:file:bg-teal-700"
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
          Загрузить
        </button>
      </motion.div>
      <p v-if="pickedFile" class="mt-2 text-xs text-slate-500">{{ pickedFile.name }} ({{ fmtSize(pickedFile.size) }})</p>
    </section>

    <details class="rounded-2xl border border-white/10 bg-slate-900/40">
      <summary class="cursor-pointer px-5 py-3.5 text-sm font-medium text-slate-300 hover:text-white">
        Синхронизация по URL (Q-Feeds и др.)
      </summary>
      <div class="space-y-4 border-t border-white/5 px-5 pb-5 pt-3">
        <p class="text-xs text-slate-500">Отключите ThreatFox выше. Авто — не чаще 2 раз в сутки.</p>
        <input
          v-model="cfg.feed_url"
          placeholder="https://api.qfeeds.com/api.php?…"
          class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
          :disabled="useThreatFox"
        />
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="text-xs text-slate-500">
            Интервал авто (сек, мин. 43200)
            <input
              v-model.number="cfg.poll_interval_sec"
              type="number"
              min="43200"
              step="3600"
              class="mt-1 block w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            />
          </label>
          <label class="text-xs text-slate-500">
            Формат
            <select v-model="cfg.format" class="mt-1 block w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-sm text-slate-200">
              <option value="auto">auto</option>
              <option value="plain">plain</option>
              <option value="csv">csv</option>
              <option value="ndjson">ndjson</option>
            </select>
          </label>
        </div>
        <button
          type="button"
          class="rounded-lg border border-teal-700/80 px-4 py-2 text-sm text-teal-100 hover:bg-slate-900 disabled:opacity-50"
          :disabled="busy || useThreatFox"
          @click="syncUrl"
        >
          Синхронизировать URL
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
  file_hash_count?: number
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
    flashOk('Синхронизация ThreatFox выполнена')
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
    flashOk('Полное обновление выполнено')
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
