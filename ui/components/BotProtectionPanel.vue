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

    <section v-if="status" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Состояние</h3>
      <p class="mt-0.5 text-xs text-slate-500">Списки и базы для блокировок</p>
      <ul class="mt-4 space-y-2 text-sm">
        <li
          v-for="s in statusPlaques"
          :key="s.key"
          class="flex flex-col gap-1 rounded-lg bg-slate-800/60 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between"
        >
          <span class="font-medium text-slate-200">{{ s.label }}</span>
          <span class="font-mono text-[10px] text-slate-500">{{ s.mono }}</span>
          <span :class="s.valueClass">{{ s.value }}</span>
        </li>
      </ul>
      <p v-if="status.last_error" class="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-100">
        {{ status.last_error }}
      </p>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 class="text-sm font-semibold text-white">Модули защиты</h3>
          <p class="mt-0.5 text-xs text-slate-500">Клик по плашке — настройки · зелёная метка — включено</p>
        </div>
        <span
          class="rounded-md px-2 py-0.5 text-xs font-medium"
          :class="cfg.enabled ? 'bg-emerald-900/50 text-emerald-300' : 'bg-slate-800 text-slate-500'"
        >
          {{ cfg.enabled ? 'шлюз: вкл' : 'шлюз: выкл' }}
        </span>
      </div>

      <ul class="mt-4 space-y-2 text-sm">
        <li
          v-for="tile in featureTiles"
          :key="tile.id"
          class="overflow-hidden rounded-lg border transition"
          :class="openPlaque === tile.id ? 'border-teal-600/40 bg-slate-800/80' : 'border-transparent bg-slate-800/60'"
        >
          <button
            type="button"
            class="flex w-full cursor-pointer flex-col gap-1 px-3 py-2.5 text-left text-xs transition hover:bg-slate-700/50 sm:flex-row sm:items-center sm:justify-between"
            :aria-expanded="openPlaque === tile.id"
            @click="togglePlaque(tile.id)"
          >
            <span class="flex min-w-0 flex-1 items-center gap-2">
              <span
                class="h-2 w-2 shrink-0 rounded-full"
                :class="tile.on ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]' : 'bg-slate-600'"
                aria-hidden="true"
              />
              <span class="font-medium text-slate-200">{{ tile.title }}</span>
            </span>
            <span class="font-mono text-[10px] text-slate-500" :title="tile.mono">{{ tile.mono }}</span>
            <span class="shrink-0 font-mono text-slate-400">{{ tile.badge }}</span>
            <span class="shrink-0 text-slate-500" aria-hidden="true">{{ openPlaque === tile.id ? '▾' : '▸' }}</span>
          </button>

          <div v-show="openPlaque === tile.id" class="border-t border-white/5 px-3 pb-4 pt-3">
            <!-- general -->
            <template v-if="tile.id === 'general'">
              <label class="flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
                Включить защиту от ботов на шлюзе
              </label>
              <label class="mt-3 flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.log_hits" type="checkbox" class="rounded border-slate-600" />
                Писать срабатывания в WAF-журнал
              </label>
            </template>

            <!-- rate_limit -->
            <template v-else-if="tile.id === 'rate_limit'">
              <label class="flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.rate_limit.enabled" type="checkbox" class="rounded border-slate-600" />
                Включить лимит (Redis)
              </label>
              <div class="mt-3 grid gap-3 sm:grid-cols-3">
                <label class="text-xs text-slate-500">
                  Запросов
                  <input v-model.number="cfg.rate_limit.requests_per_window" type="number" min="1" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" />
                </label>
                <label class="text-xs text-slate-500">
                  Окно, сек
                  <input v-model.number="cfg.rate_limit.window_sec" type="number" min="1" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" />
                </label>
                <label class="text-xs text-slate-500">
                  Область
                  <select v-model="cfg.rate_limit.scope" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200">
                    <option value="ip">ip</option>
                    <option value="ip_host">ip + host</option>
                    <option value="ip_path">ip + host + path</option>
                  </select>
                </label>
              </div>
            </template>

            <!-- scoring -->
            <template v-else-if="tile.id === 'scoring'">
              <p class="text-xs text-slate-500">User-Agent, заголовки, интервал запросов, TLS/JA3 с edge.</p>
              <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.scoring.enabled" type="checkbox" class="rounded border-slate-600" />
                Включить скоринг
              </label>
              <div class="mt-3 grid gap-3 sm:grid-cols-2">
                <label class="text-xs text-slate-500">
                  Блок при score ≥
                  <input v-model.number="cfg.scoring.block_threshold" type="number" min="1" max="100" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" />
                </label>
                <label class="text-xs text-slate-500">
                  Challenge при score ≥
                  <input v-model.number="cfg.scoring.challenge_threshold" type="number" min="1" max="100" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" />
                </label>
              </div>
              <div class="mt-4 border-t border-white/5 pt-3">
                <p class="text-xs font-medium text-slate-400">TLS / JA3</p>
                <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
                  <input v-model="cfg.tls_scoring.enabled" type="checkbox" class="rounded border-slate-600" />
                  Учитывать TLS и JA3 с прокси
                </label>
                <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
                  <input v-model="cfg.tls_scoring.block_legacy_tls" type="checkbox" class="rounded border-slate-600" />
                  Штраф за TLS &lt; 1.2
                </label>
                <textarea
                  v-model="ja3BlockStr"
                  rows="3"
                  placeholder="Заблокированные JA3 (по одному на строку)"
                  class="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
                />
              </div>
            </template>

            <!-- challenge -->
            <template v-else-if="tile.id === 'challenge'">
              <label class="flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.challenge.enabled" type="checkbox" class="rounded border-slate-600" />
                Cookie-проверка браузера
              </label>
              <div class="mt-3 grid gap-3 sm:grid-cols-2">
                <label class="text-xs text-slate-500">
                  Имя cookie
                  <input v-model="cfg.challenge.cookie_name" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-sm" />
                </label>
                <label class="text-xs text-slate-500">
                  TTL, сек
                  <input v-model.number="cfg.challenge.ttl_sec" type="number" min="60" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" />
                </label>
                <label class="text-xs text-slate-500 sm:col-span-2">
                  Секрет HMAC
                  <input
                    v-model="cfg.challenge.secret"
                    type="password"
                    class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-sm"
                    :placeholder="challengeSecretSet ? 'задан — пусто = не менять' : 'сгенерируется при сохранении'"
                  />
                </label>
              </div>
            </template>

            <!-- geo -->
            <template v-else-if="tile.id === 'geo'">
              <label class="flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.geo_block.enabled" type="checkbox" class="rounded border-slate-600" />
                Блокировать страны (Country MMDB на шлюзе)
              </label>
              <input
                v-model="geoBlockStr"
                class="mt-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
                placeholder="RU, CN, KP"
              />
            </template>

            <!-- lists -->
            <template v-else-if="tile.id === 'lists'">
              <label class="flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.asn_block.enabled" type="checkbox" class="rounded border-slate-600" />
                Блок по ASN
              </label>
              <label class="mt-2 flex items-center gap-2 text-sm text-slate-300">
                <input v-model="cfg.cidr_block.enabled" type="checkbox" class="rounded border-slate-600" />
                Блок по CIDR (датацентры)
              </label>
              <ul class="mt-4 space-y-2">
                <li
                  v-for="up in uploadPlaques"
                  :key="up.key"
                  class="flex flex-col gap-2 rounded-lg bg-slate-900/60 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div class="min-w-0">
                    <span class="text-xs font-medium text-slate-300">{{ up.label }}</span>
                    <p class="text-[10px] text-slate-500">{{ up.hint }}</p>
                  </div>
                  <div class="flex shrink-0 flex-wrap items-center gap-2">
                    <input type="file" :accept="up.accept" class="max-w-[12rem] text-[10px] text-slate-400" :disabled="busy" @change="up.onChange" />
                    <button
                      type="button"
                      class="rounded-lg border border-teal-700/50 bg-teal-950/50 px-2.5 py-1 text-[10px] font-medium text-teal-100 hover:bg-teal-900/40 disabled:opacity-40"
                      :disabled="busy || !up.hasFile"
                      @click="up.onUpload"
                    >
                      Загрузить
                    </button>
                  </div>
                </li>
              </ul>
            </template>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

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

type FeatureTile = {
  id: string
  title: string
  mono: string
  badge: string
  on: boolean
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
const openPlaque = ref<string | null>('general')
const err = ref('')
const ok = ref('')
const busy = ref(false)
const asnMmdbFile = ref<File | null>(null)
const asnListFile = ref<File | null>(null)
const cidrListFile = ref<File | null>(null)

const statusPlaques = computed(() => {
  const st = status.value
  if (!st) return []
  return [
    {
      key: 'asn',
      label: 'ASN в списке',
      mono: 'bot_protection_asn',
      value: String(st.asn_rows),
      valueClass: 'font-mono text-teal-300',
    },
    {
      key: 'cidr',
      label: 'CIDR в списке',
      mono: 'bot_protection_cidr',
      value: String(st.cidr_rows),
      valueClass: 'font-mono text-slate-300',
    },
    {
      key: 'mmdb',
      label: 'ASN MMDB',
      mono: 'GeoLite2-ASN',
      value: st.asn_mmdb_present ? 'есть' : 'нет',
      valueClass: st.asn_mmdb_present ? 'text-emerald-300' : 'text-amber-300',
    },
  ]
})

const featureTiles = computed((): FeatureTile[] => {
  const c = cfg.value
  const geoN = (c.geo_block.blocked_countries || []).length
  const ja3N = (c.tls_scoring.blocked_ja3_hashes || []).length
  return [
    {
      id: 'general',
      title: 'Общее',
      mono: 'enabled · log_hits',
      badge: c.enabled ? 'вкл' : 'выкл',
      on: c.enabled,
    },
    {
      id: 'rate_limit',
      title: 'Rate limit',
      mono: 'bot_rate_limit',
      badge: c.rate_limit.enabled ? `${c.rate_limit.requests_per_window}/${c.rate_limit.window_sec}s` : 'выкл',
      on: c.rate_limit.enabled,
    },
    {
      id: 'scoring',
      title: 'Поведенческий скоринг',
      mono: 'bot_score_block · bot_score_log',
      badge: c.scoring.enabled ? `≥${c.scoring.block_threshold}` : 'выкл',
      on: c.scoring.enabled,
    },
    {
      id: 'challenge',
      title: 'Cookie challenge',
      mono: 'bot_challenge',
      badge: c.challenge.enabled ? c.challenge.cookie_name : 'выкл',
      on: c.challenge.enabled,
    },
    {
      id: 'geo',
      title: 'GeoIP block',
      mono: 'geo_block',
      badge: c.geo_block.enabled ? `${geoN} стр.` : 'выкл',
      on: c.geo_block.enabled,
    },
    {
      id: 'lists',
      title: 'ASN / датацентры',
      mono: 'bot_asn_block · bot_cidr_block',
      badge: [c.asn_block.enabled && 'ASN', c.cidr_block.enabled && 'CIDR'].filter(Boolean).join('+') || 'выкл',
      on: c.asn_block.enabled || c.cidr_block.enabled,
    },
  ]
})

const uploadPlaques = computed(() => [
  {
    key: 'mmdb',
    label: 'GeoLite2-ASN.mmdb',
    hint: 'IP → номер ASN',
    accept: '.mmdb',
    hasFile: !!asnMmdbFile.value,
    onChange: onAsnMmdb,
    onUpload: uploadAsnMmdb,
  },
  {
    key: 'asn',
    label: 'ASN.txt',
    hint: '15169 или AS15169',
    accept: '.txt,text/plain',
    hasFile: !!asnListFile.value,
    onChange: onAsnList,
    onUpload: () => uploadList('asn'),
  },
  {
    key: 'cidr',
    label: 'CIDR.txt',
    hint: 'один IP/CIDR на строку',
    accept: '.txt,text/plain',
    hasFile: !!cidrListFile.value,
    onChange: onCidrList,
    onUpload: () => uploadList('cidr'),
  },
])

function togglePlaque(id: string) {
  openPlaque.value = openPlaque.value === id ? null : id
}

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
    await apiFetch(apiUrl('/settings/bot-protection'), { method: 'PUT', body: bodyFromForm() })
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
    await apiFetch(apiUrl('/settings/bot-protection/asn-mmdb'), { method: 'POST', body: fd })
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
