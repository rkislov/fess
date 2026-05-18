<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <div class="flex flex-wrap gap-2">
      <button type="button" class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700" :disabled="busy" @click="load">
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
    </div>

    <section v-if="status" class="grid gap-3 text-sm sm:grid-cols-3">
      <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
        <span class="text-slate-500">ASN в списке</span>
        <span class="ml-2 font-mono text-teal-200">{{ status.asn_rows }}</span>
      </div>
      <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
        <span class="text-slate-500">CIDR в списке</span>
        <span class="ml-2 font-mono text-slate-200">{{ status.cidr_rows }}</span>
      </div>
      <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">
        <span class="text-slate-500">ASN MMDB</span>
        <span class="ml-2" :class="status.asn_mmdb_present ? 'text-emerald-300' : 'text-amber-300'">
          {{ status.asn_mmdb_present ? 'загружена' : 'нет' }}
        </span>
      </div>
      <p v-if="status.last_error" class="sm:col-span-3 rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-xs text-amber-100">
        {{ status.last_error }}
      </p>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">Общее</h2>
      <label class="mt-4 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
        Включить защиту от ботов на шлюзе
      </label>
      <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.log_hits" type="checkbox" class="rounded border-slate-600" />
        Писать срабатывания в WAF-журнал
      </label>
    </section>

    <section class="rounded-2xl border border-teal-900/40 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">Rate limit (Redis)</h2>
      <label class="mt-3 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.rate_limit.enabled" type="checkbox" class="rounded border-slate-600" />
        Включить
      </label>
      <div class="mt-4 grid gap-3 sm:grid-cols-3">
        <input
          v-model.number="cfg.rate_limit.requests_per_window"
          type="number"
          min="1"
          class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          placeholder="Запросов"
        />
        <input
          v-model.number="cfg.rate_limit.window_sec"
          type="number"
          min="1"
          class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          placeholder="Окно, сек"
        />
        <select v-model="cfg.rate_limit.scope" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
          <option value="ip">ip</option>
          <option value="ip_host">ip + host</option>
          <option value="ip_path">ip + host + path</option>
        </select>
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">Поведенческий скоринг</h2>
      <p class="mt-1 text-xs text-slate-500">User-Agent, заголовки, интервал запросов, TLS/JA3 (если есть на edge).</p>
      <label class="mt-3 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.scoring.enabled" type="checkbox" class="rounded border-slate-600" />
        Включить скоринг
      </label>
      <div class="mt-3 grid gap-3 sm:grid-cols-2">
        <label class="text-sm text-slate-400">
          Блок при score ≥
          <input v-model.number="cfg.scoring.block_threshold" type="number" min="1" max="100" class="ml-2 w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1" />
        </label>
        <label class="text-sm text-slate-400">
          Challenge при score ≥
          <input v-model.number="cfg.scoring.challenge_threshold" type="number" min="1" max="100" class="ml-2 w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1" />
        </label>
      </div>
      <div class="mt-4 border-t border-white/5 pt-4">
        <h3 class="text-sm font-medium text-slate-300">TLS / JA3</h3>
        <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.tls_scoring.enabled" type="checkbox" class="rounded border-slate-600" />
          Учитывать TLS и заголовки JA3 с прокси
        </label>
        <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
          <input v-model="cfg.tls_scoring.block_legacy_tls" type="checkbox" class="rounded border-slate-600" />
          Штраф за TLS &lt; 1.2 (если шлюз терминирует TLS)
        </label>
        <textarea
          v-model="ja3BlockStr"
          rows="3"
          placeholder="Заблокированные JA3 (по одному на строку)"
          class="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
        />
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">Cookie / session challenge</h2>
      <label class="mt-3 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.challenge.enabled" type="checkbox" class="rounded border-slate-600" />
        Требовать проверку браузера (cookie)
      </label>
      <div class="mt-3 grid gap-3 sm:grid-cols-2">
        <input v-model="cfg.challenge.cookie_name" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono" placeholder="Имя cookie" />
        <input v-model.number="cfg.challenge.ttl_sec" type="number" min="60" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" placeholder="TTL, сек" />
        <input
          v-model="cfg.challenge.secret"
          type="password"
          class="sm:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
          :placeholder="challengeSecretSet ? 'Секрет задан (пусто = не менять)' : 'Секрет HMAC (или сгенерируется при сохранении)'"
        />
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">GeoIP block</h2>
      <label class="mt-3 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.geo_block.enabled" type="checkbox" class="rounded border-slate-600" />
        Блокировать страны (нужна Country MMDB на шлюзе)
      </label>
      <input
        v-model="geoBlockStr"
        class="mt-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
        placeholder="RU, CN, KP — через запятую или с новой строки"
      />
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">ASN и датацентры</h2>
      <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.asn_block.enabled" type="checkbox" class="rounded border-slate-600" />
        Блок по номерам ASN
      </label>
      <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
        <input v-model="cfg.cidr_block.enabled" type="checkbox" class="rounded border-slate-600" />
        Блок по CIDR (датацентры)
      </label>

      <div class="mt-4 space-y-4">
        <div>
          <p class="text-xs text-slate-500">GeoLite2-ASN.mmdb — для сопоставления IP → ASN</p>
          <input type="file" accept=".mmdb" class="mt-2 text-sm text-slate-300" :disabled="busy" @change="onAsnMmdb" />
          <button type="button" class="ml-2 rounded-lg bg-teal-800 px-3 py-1.5 text-xs text-white" :disabled="busy || !asnMmdbFile" @click="uploadAsnMmdb">
            Загрузить MMDB
          </button>
        </div>
        <div>
          <p class="text-xs text-slate-500">ASN.txt — один номер на строку (15169 или AS15169)</p>
          <input type="file" accept=".txt,text/plain" class="mt-2 text-sm" :disabled="busy" @change="onAsnList" />
          <button type="button" class="ml-2 rounded-lg bg-teal-800 px-3 py-1.5 text-xs text-white" :disabled="busy || !asnListFile" @click="uploadList('asn')">
            Загрузить ASN
          </button>
        </div>
        <div>
          <p class="text-xs text-slate-500">CIDR.txt — один IP/CIDR на строку</p>
          <input type="file" accept=".txt,text/plain" class="mt-2 text-sm" :disabled="busy" @change="onCidrList" />
          <button type="button" class="ml-2 rounded-lg bg-teal-800 px-3 py-1.5 text-xs text-white" :disabled="busy || !cidrListFile" @click="uploadList('cidr')">
            Загрузить CIDR
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl } = useApi()

type BotCfg = {
  enabled: boolean
  log_hits: boolean
  rate_limit: { enabled: boolean; requests_per_window: number; window_sec: number; scope: string }
  scoring: { enabled: boolean; block_threshold: number; challenge_threshold: number }
  challenge: { enabled: boolean; cookie_name: string; ttl_sec: number; secret: string }
  geo_block: { enabled: boolean; blocked_countries: string[] }
  asn_block: { enabled: boolean }
  cidr_block: { enabled: boolean }
  tls_scoring: { enabled: boolean; block_legacy_tls: boolean; trust_ja3_header: boolean; blocked_ja3_hashes: string[] }
}

type BotResp = BotCfg & { challenge_secret_set?: boolean }
type BotStatus = {
  enabled: boolean
  asn_rows: number
  cidr_rows: number
  asn_mmdb_present: boolean
  last_error?: string
}

function defaultCfg(): BotCfg {
  return {
    enabled: false,
    log_hits: true,
    rate_limit: { enabled: true, requests_per_window: 120, window_sec: 60, scope: 'ip_host' },
    scoring: { enabled: true, block_threshold: 70, challenge_threshold: 45 },
    challenge: { enabled: false, cookie_name: 'fence_bot', ttl_sec: 86400, secret: '' },
    geo_block: { enabled: false, blocked_countries: [] },
    asn_block: { enabled: false },
    cidr_block: { enabled: false },
    tls_scoring: { enabled: true, block_legacy_tls: true, trust_ja3_header: true, blocked_ja3_hashes: [] },
  }
}

const cfg = ref<BotCfg>(defaultCfg())
const status = ref<BotStatus | null>(null)
const geoBlockStr = ref('')
const ja3BlockStr = ref('')
const challengeSecretSet = ref(false)
const err = ref('')
const ok = ref('')
const busy = ref(false)
const asnMmdbFile = ref<File | null>(null)
const asnListFile = ref<File | null>(null)
const cidrListFile = ref<File | null>(null)

function flashErr(e: unknown) {
  ok.value = ''
  const fe = e as FetchError<{ error?: string }>
  err.value = fe?.data?.error || fe?.message || String(e)
}

function flashOk(msg: string) {
  err.value = ''
  ok.value = msg
  setTimeout(() => { ok.value = '' }, 5000)
}

function parseGeoList(s: string): string[] {
  return s
    .split(/[\s,;]+/)
    .map((x) => x.trim().toUpperCase())
    .filter((x) => x.length === 2)
}

function bodyFromForm() {
  const countries = parseGeoList(geoBlockStr.value)
  const ja3 = ja3BlockStr.value.split('\n').map((s) => s.trim()).filter(Boolean)
  return {
    ...cfg.value,
    geo_block: { ...cfg.value.geo_block, blocked_countries: countries },
    tls_scoring: { ...cfg.value.tls_scoring, blocked_ja3_hashes: ja3 },
  }
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const [data, st] = await Promise.all([
      $fetch<BotResp>(apiUrl('/settings/bot-protection')),
      $fetch<BotStatus>(apiUrl('/settings/bot-protection/status')),
    ])
    challengeSecretSet.value = !!data.challenge_secret_set
    const { challenge_secret_set: _s, ...rest } = data
    cfg.value = { ...defaultCfg(), ...rest }
    geoBlockStr.value = (cfg.value.geo_block.blocked_countries || []).join(', ')
    ja3BlockStr.value = (cfg.value.tls_scoring.blocked_ja3_hashes || []).join('\n')
    status.value = st
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function save() {
  busy.value = true
  try {
    await $fetch(apiUrl('/settings/bot-protection'), { method: 'PUT', body: bodyFromForm() })
    await load()
    flashOk('Сохранено')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

function onAsnMmdb(ev: Event) {
  asnMmdbFile.value = (ev.target as HTMLInputElement).files?.[0] ?? null
}
function onAsnList(ev: Event) {
  asnListFile.value = (ev.target as HTMLInputElement).files?.[0] ?? null
}
function onCidrList(ev: Event) {
  cidrListFile.value = (ev.target as HTMLInputElement).files?.[0] ?? null
}

async function uploadAsnMmdb() {
  const f = asnMmdbFile.value
  if (!f) return
  busy.value = true
  try {
    const fd = new FormData()
    fd.append('file', f, f.name)
    await $fetch(apiUrl('/settings/bot-protection/asn-mmdb'), { method: 'POST', body: fd })
    asnMmdbFile.value = null
    await load()
    flashOk('ASN MMDB загружена')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function uploadList(type: 'asn' | 'cidr') {
  const f = type === 'asn' ? asnListFile.value : cidrListFile.value
  if (!f) return
  busy.value = true
  try {
    const fd = new FormData()
    fd.append('file', f, f.name)
    const res = await $fetch<{ rows_ingested: number }>(apiUrl(`/settings/bot-protection/upload?type=${type}`), {
      method: 'POST',
      body: fd,
    })
    if (type === 'asn') asnListFile.value = null
    else cidrListFile.value = null
    await load()
    flashOk(`Загружено ${res.rows_ingested} записей (${type})`)
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>
