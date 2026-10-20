<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Срабатывания правил WAF</h2>
      <p class="mt-1 text-sm text-slate-400">
        Записи из шлюза: сработала конкретная политика/правило, блокировка вредоносного ПО и эффективное действие.
      </p>
      <LogQueryBar
        class="mt-4"
        v-model:q="searchQ"
        v-model:hours="hours"
        @apply="onSearch"
        @reset="onReset"
      >
        <template #filters>
          <label class="shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">Действие</span>
            <input
              v-model="filterAction"
              type="text"
              placeholder="block, log…"
              class="h-[38px] w-28 rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm text-white"
            />
          </label>
          <label class="shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">IP</span>
            <input
              v-model="filterIP"
              type="text"
              class="h-[38px] w-32 rounded-lg border border-slate-600 bg-slate-800 px-2 font-mono text-sm text-white"
            />
          </label>
          <label class="min-w-[8rem] shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">Host</span>
            <input
              v-model="filterHost"
              type="text"
              class="h-[38px] w-full min-w-[8rem] rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm text-white"
            />
          </label>
          <label class="min-w-[10rem] shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">Правило (UUID)</span>
            <input
              v-model="filterRule"
              type="text"
              class="h-[38px] w-full min-w-[10rem] rounded-lg border border-slate-600 bg-slate-800 px-2 font-mono text-xs text-white"
            />
          </label>
        </template>
      </LogQueryBar>
      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="py-2 pr-3">Время</th>
              <th class="py-2 pr-3">Действие</th>
              <th class="py-2 pr-3">Политика</th>
              <th class="py-2 pr-3">Правило</th>
              <th class="py-2 pr-3">Правило (имя)</th>
              <th class="py-2 pr-3">IP</th>
              <th class="py-2 pr-3">Запрос</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!items.length && !busy">
              <td colspan="7" class="py-8 text-center text-slate-500">Нет записей — правила пишутся при совпадении (и при блоке malware)</td>
            </tr>
            <tr
              v-for="(it, idx) in items"
              :key="rowKey(it, idx)"
              class="cursor-pointer border-b border-slate-800/80 transition hover:bg-slate-800/40"
              @click="openDetail(it)"
            >
              <td class="whitespace-nowrap py-2 pr-3 font-mono text-xs text-slate-400">{{ fmt(it.created_at) }}</td>
              <td class="py-2 pr-3">
                <span class="rounded-md bg-slate-800 px-2 py-0.5 text-xs">{{ it.action }}</span>
              </td>
              <td class="max-w-[120px] truncate py-2 pr-3 font-mono text-xs" :title="it.policy_id">{{ it.policy_id || '—' }}</td>
              <td class="max-w-[120px] truncate py-2 pr-3 font-mono text-xs" :title="it.rule_id">{{ it.rule_id || '—' }}</td>
              <td class="max-w-[180px] truncate py-2 pr-3 text-slate-300" :title="reason(it)">{{ reason(it) }}</td>
              <td class="py-2 pr-3 font-mono text-xs">{{ it.source_ip }}</td>
              <td class="max-w-[160px] truncate py-2 font-mono text-xs" :title="it.method + ' ' + it.path">
                {{ it.method }} {{ it.path }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <LogPaginationBar
        class="mt-4"
        :total="total"
        :page="page"
        :page-size="pageSize"
        :busy="busy"
        @update:page="onPage"
        @update:page-size="onPageSize"
      />
    </section>
  </div>
</template>

<script setup lang="ts">
const { apiUrl, apiFetch } = useApi()
const { openWafEventDetail } = useHashAppView()

type Row = {
  id?: number
  request_id: string
  policy_id: string
  rule_id: string
  action: string
  source_ip: string
  method: string
  path: string
  details?: Record<string, unknown> | null
  created_at: string
}

const items = ref<Row[]>([])
const err = ref('')
const busy = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(100)
const searchQ = ref('')
const hours = ref(0)
const filterAction = ref('')
const filterIP = ref('')
const filterHost = ref('')
const filterRule = ref('')

function onSearch() {
  page.value = 1
  void load()
}

function onReset() {
  searchQ.value = ''
  hours.value = 0
  filterAction.value = ''
  filterIP.value = ''
  filterHost.value = ''
  filterRule.value = ''
  page.value = 1
  void load()
}

function rowKey(it: Row, idx: number) {
  return it.id ? String(it.id) : `${it.request_id}:${it.created_at}:${idx}`
}

function openDetail(it: Row) {
  if (it.id && it.id > 0) {
    openWafEventDetail(it.id)
  }
}

function onPage(p: number) {
  page.value = p
  void load()
}

function onPageSize(n: number) {
  pageSize.value = n
  page.value = 1
  void load()
}

function fmt(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}

function reason(it: Row) {
  const d = it.details
  if (d && typeof d === 'object') {
    if ('detail' in d && typeof (d as { detail?: string }).detail === 'string') {
      const src = 'source' in d && typeof (d as { source?: string }).source === 'string' ? (d as { source: string }).source : ''
      const det = (d as { detail: string }).detail
      return src ? `${src}: ${det}` : det
    }
    if ('reason' in d && typeof (d as { reason?: string }).reason === 'string') {
      return (d as { reason: string }).reason
    }
  }
  return '—'
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const offset = (page.value - 1) * pageSize.value
    const q = new URLSearchParams({ limit: String(pageSize.value), offset: String(offset) })
    appendLogQueryBase(q, { q: searchQ.value, hours: hours.value })
    appendIfSet(q, 'action', filterAction.value)
    appendIfSet(q, 'source_ip', filterIP.value)
    appendIfSet(q, 'host', filterHost.value)
    appendIfSet(q, 'rule_id', filterRule.value)
    const data = await apiFetch<{ items: Row[]; total: number; limit: number; offset: number }>(
      apiUrl(`/logs?${q.toString()}`),
    )
    items.value = data.items || []
    total.value = typeof data.total === 'number' ? data.total : 0
    const pages = Math.max(1, Math.ceil(total.value / pageSize.value))
    if (page.value > pages) page.value = pages
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => load())
</script>
