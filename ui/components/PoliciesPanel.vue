<template>
  <div class="space-y-8">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/25 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Policies</h2>
      <p class="mt-1 text-sm text-slate-400">Create, edit, publish. Rules use JSON condition/transform schemas.</p>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          v-for="p in policies"
          :key="p.id"
          type="button"
          class="rounded-lg border px-3 py-1.5 text-sm transition"
          :class="
            selectedId === p.id
              ? 'border-emerald-500 bg-emerald-950/50 text-emerald-100'
              : 'border-slate-700 bg-slate-800/80 text-slate-200 hover:border-slate-500'
          "
          @click="selectPolicy(p.id)"
        >
          {{ p.name }}
        </button>
        <button
          type="button"
          class="rounded-lg border border-dashed border-slate-600 px-3 py-1.5 text-sm text-slate-400 hover:border-slate-400 hover:text-slate-200"
          @click="clearSelection"
        >
          Clear
        </button>
      </div>

      <div class="mt-6 grid gap-4 border-t border-slate-800 pt-6 md:grid-cols-2">
        <div>
          <h3 class="text-sm font-medium text-slate-300">New policy</h3>
          <div class="mt-2 space-y-2">
            <input
              v-model="newPolicy.name"
              placeholder="Name"
              class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none ring-emerald-500/30 focus:ring-2"
            />
            <select
              v-model="newPolicy.mode"
              class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-emerald-500/30"
            >
              <option value="block">block</option>
              <option value="log">log</option>
            </select>
            <input
              v-model.number="newPolicy.priority"
              type="number"
              placeholder="Priority (default 100)"
              class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-emerald-500/30"
            />
            <button
              type="button"
              class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
              :disabled="busy"
              @click="createPolicy"
            >
              Create
            </button>
          </div>
        </div>

        <div v-if="detail">
          <h3 class="text-sm font-medium text-slate-300">Selected policy</h3>
          <div class="mt-2 space-y-2">
            <input
              v-model="detail.name"
              class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            />
            <select v-model="detail.mode" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
              <option value="block">block</option>
              <option value="log">log</option>
            </select>
            <input v-model.number="detail.priority" type="number" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <label class="flex items-center gap-2 text-sm text-slate-300">
              <input v-model="detail.enabled" type="checkbox" class="rounded border-slate-600" />
              Enabled
            </label>
            <div class="flex flex-wrap gap-2">
              <button
                type="button"
                class="rounded-lg bg-slate-700 px-3 py-2 text-sm hover:bg-slate-600"
                :disabled="busy"
                @click="savePolicy"
              >
                Save policy
              </button>
              <button
                type="button"
                class="rounded-lg bg-amber-600 px-3 py-2 text-sm font-medium text-white hover:bg-amber-500"
                :disabled="busy"
                @click="publishPolicy"
              >
                Publish
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section v-if="detail" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/25 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Rules</h2>
      <div class="mt-4 space-y-6">
        <div
          v-for="(r, idx) in ruleRows"
          :key="r.id"
          class="rounded-lg border border-slate-800 bg-slate-950/50 p-4"
        >
          <div class="flex flex-wrap items-end gap-2">
            <div class="min-w-[140px] flex-1">
              <label class="text-xs text-slate-500">Name</label>
              <input v-model="r.name" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
            <div class="w-28">
              <label class="text-xs text-slate-500">Action</label>
              <select v-model="r.action" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm">
                <option value="allow">allow</option>
                <option value="block">block</option>
                <option value="log">log</option>
                <option value="redirect">redirect</option>
                <option value="replace">replace</option>
              </select>
            </div>
            <div class="w-24">
              <label class="text-xs text-slate-500">Priority</label>
              <input v-model.number="r.priority" type="number" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
            <label class="flex items-center gap-2 pb-1 text-sm text-slate-400">
              <input v-model="r.enabled" type="checkbox" class="rounded border-slate-600" />
              On
            </label>
            <button type="button" class="rounded bg-slate-700 px-3 py-1.5 text-sm hover:bg-slate-600" :disabled="busy" @click="saveRule(idx)">
              Save rule
            </button>
          </div>
          <div class="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <label class="text-xs text-slate-500">condition_json</label>
              <textarea
                v-model="r.conditionText"
                rows="6"
                class="mt-1 w-full rounded border border-slate-700 bg-slate-900 font-mono text-xs leading-relaxed"
              />
            </div>
            <div>
              <label class="text-xs text-slate-500">transform_json</label>
              <textarea
                v-model="r.transformText"
                rows="6"
                class="mt-1 w-full rounded border border-slate-700 bg-slate-900 font-mono text-xs leading-relaxed"
              />
            </div>
          </div>
        </div>
      </div>

      <div class="mt-6 border-t border-slate-800 pt-6">
        <h3 class="text-sm font-medium text-slate-300">Конструктор условия</h3>
        <p class="mt-1 text-xs text-slate-500">
          Условия: <span class="font-mono text-slate-400">path_exact</span>, <span class="font-mono">path_contains</span>,
          <span class="font-mono">path_prefix</span>, <span class="font-mono">path_regex</span>,
          <span class="font-mono">client_ip_in</span> (разрешённые IP/CIDR для срабатывания правила),
          <span class="font-mono">client_ip_not_in</span> — правило <strong class="text-slate-400">пропускается</strong>, если клиент входит в
          одну из перечисленных сетей (удобная пара с <span class="font-mono">block</span>: доверенные сети не попадают под блокировку этого правила).
        </p>
        <div class="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <label class="text-xs text-slate-500">Тип условия</label>
            <select v-model="ctor.kind" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm">
              <option value="path_contains">path_contains</option>
              <option value="path_exact">path_exact</option>
              <option value="path_prefix">path_prefix (starts with)</option>
              <option value="path_and_ip_allow">path_prefix + только эти клиентские IP/CIDR</option>
              <option value="path_and_trusted_subnets">path_prefix + доверенные сети (остальные блок — см. текст)</option>
              <option value="body_contains">body_contains</option>
              <option value="request_uri_contains">request_uri_contains</option>
              <option value="path_regex">path_regex</option>
              <option value="method">method (HTTP)</option>
              <option value="header_contains">header_contains</option>
              <option value="query_equals">query_equals (одна пара)</option>
            </select>
          </div>
          <div v-if="ctor.kind === 'method'">
            <label class="text-xs text-slate-500">Метод</label>
            <select v-model="ctor.method" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm">
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
              <option>HEAD</option>
              <option>OPTIONS</option>
              <option>TRACE</option>
            </select>
          </div>
          <template v-else-if="ctor.kind === 'header_contains'">
            <div>
              <label class="text-xs text-slate-500">Имя заголовка</label>
              <input v-model="ctor.hdrKey" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
            <div>
              <label class="text-xs text-slate-500">Подстрока в значении</label>
              <input v-model="ctor.hdrVal" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
          </template>
          <template v-else-if="ctor.kind === 'query_equals'">
            <div>
              <label class="text-xs text-slate-500">Имя параметра</label>
              <input v-model="ctor.qKey" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
            <div>
              <label class="text-xs text-slate-500">Значение</label>
              <input v-model="ctor.qVal" class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm" />
            </div>
          </template>
          <template v-else-if="ctor.kind === 'path_and_ip_allow' || ctor.kind === 'path_and_trusted_subnets'">
            <div class="md:col-span-2">
              <label class="text-xs text-slate-500">Префикс пути (path_prefix)</label>
              <input
                v-model="ctor.pathValue"
                class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-sm"
                placeholder="/api/private/"
              />
            </div>
            <div class="md:col-span-2">
              <label class="text-xs text-slate-500">
                {{
                  ctor.kind === 'path_and_ip_allow'
                    ? 'IP/CIDR, с которых правило действует (по одному в строке или через запятую)'
                    : 'Доверенные IP/CIDR: для них правило не срабатывает; действие block применится к клиентам вне этого списка'
                }}
              </label>
              <textarea
                v-model="ctor.ipLines"
                rows="5"
                class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-xs"
                placeholder="10.0.0.0/8&#10;192.168.1.42"
              />
            </div>
          </template>
          <div v-else class="md:col-span-2">
            <label class="text-xs text-slate-500">Строка или регулярное выражение (path_regex)</label>
            <input
              v-model="ctor.value"
              class="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-xs"
              placeholder="например /admin или ^/api/v[0-9]+/"
            />
          </div>
        </div>
        <pre class="mt-3 max-h-40 overflow-auto rounded border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">{{ ctorPreview }}</pre>
        <button
          type="button"
          class="mt-3 rounded-lg bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-600"
          @click="applyCtorToNewRule"
        >
          Вставить в форму «Добавить правило»
        </button>
      </div>

      <div class="mt-6 border-t border-slate-800 pt-6">
        <h3 class="text-sm font-medium text-slate-300">Add rule</h3>
        <div class="mt-2 space-y-2">
          <input v-model="newRule.name" placeholder="Name" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          <select v-model="newRule.action" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
            <option value="block">block</option>
            <option value="log">log</option>
            <option value="allow">allow</option>
            <option value="redirect">redirect</option>
            <option value="replace">replace</option>
          </select>
          <input v-model.number="newRule.priority" type="number" placeholder="Priority" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          <textarea
            v-model="newRule.conditionText"
            rows="4"
            placeholder='condition JSON e.g. {"path_contains":"/admin"}'
            class="w-full rounded-lg border border-slate-700 bg-slate-950 font-mono text-xs"
          />
          <textarea
            v-model="newRule.transformText"
            rows="3"
            placeholder="transform JSON (optional)"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 font-mono text-xs"
          />
          <button type="button" class="rounded-lg bg-emerald-700 px-4 py-2 text-sm hover:bg-emerald-600" :disabled="busy || !detail" @click="addRule">
            Add rule
          </button>
        </div>
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/25 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">OWASP packs</h2>
      <p class="mt-1 text-sm text-slate-400">
        Импорт встроенных наборов: <strong class="text-slate-200">crs-bundle-v1</strong> — полный набор эвристик; <strong class="text-slate-200">crs-lite-v1</strong> — 15
        правил для тестов. Импорт создаёт <em>все</em> правила пакета в новой политике.
      </p>
      <div class="mt-4 grid gap-3 md:grid-cols-2">
        <select v-model="owasp.packId" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
          <option v-for="p in packs" :key="p.id" :value="p.id">{{ p.title }} ({{ p.rule_count }} rules)</option>
        </select>
        <p v-if="selectedPack" class="text-xs text-slate-500 md:col-span-2">
          Выбрано правил: <span class="font-mono text-slate-300">{{ selectedPack.rule_count }}</span>
        </p>
        <input v-model="owasp.policyName" placeholder="Policy name" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        <select v-model="owasp.mode" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
          <option value="block">block</option>
          <option value="log">log</option>
        </select>
        <input v-model.number="owasp.priority" type="number" class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        <label class="flex items-center gap-2 text-sm text-slate-300 md:col-span-2">
          <input v-model="owasp.publish" type="checkbox" class="rounded border-slate-600" />
          Publish after import
        </label>
        <div class="flex flex-wrap gap-2 md:col-span-2">
          <button
            type="button"
            class="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
            :disabled="busy || !owasp.packId"
            @click="downloadOwaspPack"
          >
            Скачать JSON пака
          </button>
          <button
            type="button"
            class="rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-500"
            :disabled="busy"
            @click="importOwasp"
          >
            Import pack
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

const err = ref('')
const ok = ref('')
const busy = ref(false)
const policies = ref<{ id: string; name: string; mode: string; priority: number; enabled: boolean }[]>([])
const selectedId = ref<string | null>(null)
const detail = ref<{
  id: string
  name: string
  mode: string
  priority: number
  enabled: boolean
} | null>(null)

type RuleRow = {
  id: string
  name: string
  action: string
  priority: number
  enabled: boolean
  conditionText: string
  transformText: string
}
const ruleRows = ref<RuleRow[]>([])

const newPolicy = reactive({ name: '', mode: 'block' as 'block' | 'log', priority: 0 })
const newRule = reactive({
  name: '',
  action: 'block',
  priority: 0,
  conditionText: '{}',
  transformText: '{}',
})

const ctor = reactive({
  kind: 'path_contains',
  value: '',
  pathValue: '',
  ipLines: '',
  method: 'GET',
  hdrKey: 'User-Agent',
  hdrVal: '',
  qKey: '',
  qVal: '',
})

const packs = ref<{ id: string; title: string; rule_count: number }[]>([])
const owasp = reactive({
  packId: '',
  policyName: 'OWASP CRS',
  mode: 'block' as 'block' | 'log',
  priority: 50,
  publish: true,
})

const selectedPack = computed(() => packs.value.find((p) => p.id === owasp.packId))

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

async function loadPolicies() {
  const data = await apiFetch<{ items: typeof policies.value }>(apiUrl('/policies'))
  policies.value = data.items || []
}

async function loadPacks() {
  const data = await apiFetch<{ items: typeof packs.value }>(apiUrl('/owasp/packs'))
  packs.value = data.items || []
  const prefer = packs.value.find((p) => p.id === 'crs-bundle-v1')
  owasp.packId = prefer?.id || packs.value[0]?.id || ''
}

function parseIPCIDRMultiline(raw: string): string[] {
  const parts = raw
    .split(/[\s,;\n\r]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  return [...new Set(parts)]
}

function buildCtorCondition(): Record<string, unknown> {
  const k = ctor.kind
  if (k === 'method') {
    return { method: ctor.method }
  }
  if (k === 'header_contains') {
    const key = ctor.hdrKey.trim()
    if (!key) return {}
    return { header_contains: { [key]: ctor.hdrVal } }
  }
  if (k === 'query_equals') {
    const qk = ctor.qKey.trim()
    if (!qk) return {}
    return { query_equals: { [qk]: ctor.qVal } }
  }
  if (k === 'path_and_ip_allow' || k === 'path_and_trusted_subnets') {
    const p = ctor.pathValue.trim()
    const ips = parseIPCIDRMultiline(ctor.ipLines)
    if (!p || !ips.length) return {}
    if (k === 'path_and_ip_allow') {
      return { path_prefix: p, client_ip_in: ips }
    }
    return { path_prefix: p, client_ip_not_in: ips }
  }
  const v = typeof ctor.value === 'string' ? ctor.value.trim() : ''
  if (!v) return {}
  switch (k) {
    case 'path_contains':
      return { path_contains: v }
    case 'path_exact':
      return { path_exact: v }
    case 'path_prefix':
      return { path_prefix: v }
    case 'body_contains':
      return { body_contains: v }
    case 'request_uri_contains':
      return { request_uri_contains: v }
    case 'path_regex':
      return { path_regex: v }
    default:
      return {}
  }
}

const ctorPreview = computed(() => {
  try {
    return JSON.stringify(buildCtorCondition(), null, 2)
  } catch {
    return '{}'
  }
})

function applyCtorToNewRule() {
  const o = buildCtorCondition()
  if (!Object.keys(o).length) {
    flashErr(new Error('Заполните поля конструктора'))
    return
  }
  newRule.conditionText = JSON.stringify(o, null, 2)
  flashOk('Условие вставлено в форму добавления правила')
}

async function downloadOwaspPack() {
  if (!owasp.packId) return
  busy.value = true
  err.value = ''
  try {
    const u = `${apiUrl('/owasp/pack')}?pack_id=${encodeURIComponent(owasp.packId)}`
    const res = await fetch(u)
    if (!res.ok) {
      const t = await res.text()
      throw new Error(t || res.statusText)
    }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `fence-owasp-${owasp.packId}.json`
    a.rel = 'noopener'
    a.click()
    URL.revokeObjectURL(a.href)
    flashOk('Файл пака скачан')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

function stringifyJson(raw: unknown) {
  if (raw == null) return '{}'
  if (typeof raw === 'string') {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2)
    } catch {
      return raw
    }
  }
  return JSON.stringify(raw, null, 2)
}

async function selectPolicy(id: string) {
  err.value = ''
  selectedId.value = id
  busy.value = true
  try {
    const d = await apiFetch<{
      id: string
      name: string
      mode: string
      priority: number
      enabled: boolean
      rules: {
        id: string
        name: string
        action: string
        priority: number
        enabled: boolean
        condition_json: unknown
        transform_json: unknown
      }[]
    }>(apiUrl(`/policies/${id}`))
    detail.value = {
      id: d.id,
      name: d.name,
      mode: d.mode,
      priority: d.priority,
      enabled: d.enabled,
    }
    ruleRows.value = (d.rules || []).map((r) => ({
      id: r.id,
      name: r.name,
      action: r.action,
      priority: r.priority,
      enabled: r.enabled,
      conditionText: stringifyJson(r.condition_json),
      transformText: stringifyJson(r.transform_json),
    }))
  } catch (e) {
    flashErr(e)
    detail.value = null
    ruleRows.value = []
  } finally {
    busy.value = false
  }
}

function clearSelection() {
  selectedId.value = null
  detail.value = null
  ruleRows.value = []
}

async function createPolicy() {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/policies'), {
      method: 'POST',
      body: {
        name: newPolicy.name,
        mode: newPolicy.mode,
        priority: newPolicy.priority || undefined,
      },
    })
    newPolicy.name = ''
    await loadPolicies()
    flashOk('Policy created')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function savePolicy() {
  if (!detail.value) return
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl(`/policies/${detail.value.id}`), {
      method: 'PUT',
      body: {
        name: detail.value.name,
        mode: detail.value.mode,
        priority: detail.value.priority,
        enabled: detail.value.enabled,
      },
    })
    await loadPolicies()
    flashOk('Policy saved')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function publishPolicy() {
  if (!detail.value) return
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl(`/policies/${detail.value.id}/publish`), { method: 'POST' })
    flashOk('Published')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

function parseJsonField(text: string, field: string) {
  const t = text.trim() || '{}'
  try {
    return JSON.parse(t) as object
  } catch {
    throw new Error(`Invalid JSON in ${field}`)
  }
}

async function saveRule(idx: number) {
  const r = ruleRows.value[idx]
  if (!r) return
  busy.value = true
  err.value = ''
  try {
    const condition_json = parseJsonField(r.conditionText, 'condition_json')
    const transform_json = parseJsonField(r.transformText, 'transform_json')
    await apiFetch(apiUrl(`/rules/${r.id}`), {
      method: 'PUT',
      body: {
        name: r.name,
        action: r.action,
        priority: r.priority,
        enabled: r.enabled,
        condition_json,
        transform_json,
      },
    })
    flashOk('Rule saved')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function addRule() {
  if (!detail.value) return
  busy.value = true
  err.value = ''
  try {
    const condition_json = parseJsonField(newRule.conditionText, 'condition_json')
    const transform_json = parseJsonField(newRule.transformText || '{}', 'transform_json')
    await apiFetch(apiUrl(`/policies/${detail.value.id}/rules`), {
      method: 'POST',
      body: {
        name: newRule.name,
        action: newRule.action,
        priority: newRule.priority || undefined,
        condition_json,
        transform_json,
      },
    })
    newRule.name = ''
    newRule.conditionText = '{}'
    newRule.transformText = '{}'
    await selectPolicy(detail.value.id)
    flashOk('Rule added')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function importOwasp() {
  busy.value = true
  err.value = ''
  try {
    const res = await apiFetch<{ policy_id: string }>(apiUrl('/owasp/import'), {
      method: 'POST',
      body: {
        pack_id: owasp.packId,
        policy_name: owasp.policyName,
        mode: owasp.mode,
        priority: owasp.priority || undefined,
        publish: owasp.publish,
        published_by: 'ui',
      },
    })
    await loadPolicies()
    if (res.policy_id) await selectPolicy(res.policy_id)
    flashOk('OWASP pack imported')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(async () => {
  try {
    await Promise.all([loadPolicies(), loadPacks()])
  } catch (e) {
    flashErr(e)
  }
})
</script>
