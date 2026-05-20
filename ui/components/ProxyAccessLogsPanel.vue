<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Соединения к сайтам</h2>
      <p class="mt-1 text-sm text-slate-400">
        Запросы через WAF: виртуальный хост, выбранный бэкенд (первый по приоритету среди включённых), upstream URL, итог.
        Колонка <strong class="text-slate-300">Host</strong> — имя из запроса (в Go это поле
        <span class="font-mono text-slate-400">Host</span> / HTTP/2 <span class="font-mono text-slate-400">:authority</span>, не всегда дублируется в заголовке
        <span class="font-mono text-slate-400">Host</span>).
        Колонка <strong class="text-slate-300">Клиент</strong> — эффективный IP (из
        <span class="font-mono text-slate-400">X-Forwarded-For</span> / Real-IP, если на шлюзе задан
        <span class="font-mono text-slate-400">WAF_TRUSTED_PROXIES</span>); <strong class="text-slate-300">TCP пир</strong> — кто
        реально подключился к шлюзу (часто IP балансировщика).
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
            <span class="mb-1 block text-xs font-medium text-slate-500">Итог</span>
            <select
              v-model="filterOutcome"
              class="h-[38px] rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm text-white"
            >
              <option value="">Все</option>
              <option value="proxied">Проксировано</option>
              <option value="waf_block">Блок WAF</option>
              <option value="malware_block">Антивирус</option>
              <option value="redirect">Редирект</option>
            </select>
          </label>
          <label class="shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">Метод</span>
            <input
              v-model="filterMethod"
              type="text"
              class="h-[38px] w-20 rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm uppercase text-white"
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
          <label class="shrink-0">
            <span class="mb-1 block text-xs font-medium text-slate-500">Клиент IP</span>
            <input
              v-model="filterClientIP"
              type="text"
              class="h-[38px] w-32 rounded-lg border border-slate-600 bg-slate-800 px-2 font-mono text-sm text-white"
            />
          </label>
        </template>
      </LogQueryBar>
      <div class="mt-4 max-h-[min(70vh,52rem)] overflow-auto rounded-lg border border-slate-800/80">
        <table class="min-w-[1280px] border-separate border-spacing-0 text-left text-sm">
          <thead class="sticky top-0 z-10 border-b border-slate-700 bg-slate-900/95 text-slate-500 shadow-[inset_0_-1px_0_0_rgba(51,65,85,0.9)] backdrop-blur-sm">
            <tr>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Время</th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Host</th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Метод</th>
              <th
                class="min-w-[14rem] max-w-[26rem] px-3 py-2.5 text-left align-bottom font-medium"
                title="HTTP User-Agent клиента"
              >
                User-Agent
              </th>
              <th class="min-w-[12rem] max-w-[22rem] px-3 py-2.5 text-left align-bottom font-medium">Путь</th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium" title="После LB, если настроен WAF_TRUSTED_PROXIES">
                Клиент
              </th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium" title="TCP RemoteAddr (часто балансировщик)">
                TCP пир
              </th>
              <th class="min-w-[6rem] max-w-[12rem] px-3 py-2.5 text-left align-bottom font-medium" title="Имя строки бэкенда (первый по приоритету)">
                Бэкенд
              </th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Протокол</th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Страна</th>
              <th class="min-w-[10rem] max-w-[18rem] px-3 py-2.5 text-left align-bottom font-medium">Upstream URL</th>
              <th class="whitespace-nowrap px-3 py-2.5 text-left align-bottom font-medium">Итог</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!items.length && !busy">
              <td colspan="12" class="py-8 text-center text-slate-500">Нет данных — сделайте несколько запросов через шлюз и нажмите «Обновить»</td>
            </tr>
            <tr v-for="it in items" :key="it.id" class="border-b border-slate-800/80 align-top hover:bg-slate-800/20">
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-400">{{ fmt(it.created_at) }}</td>
              <td class="max-w-[12rem] whitespace-normal break-words px-3 py-2.5 font-mono text-xs" :title="it.host">{{ it.host || '—' }}</td>
              <td class="whitespace-nowrap px-3 py-2.5 font-medium">{{ it.method }}</td>
              <td
                class="max-w-[26rem] whitespace-normal break-words px-3 py-2.5 font-mono text-[11px] leading-snug text-slate-300"
                :title="it.user_agent || ''"
              >
                {{ it.user_agent || '—' }}
              </td>
              <td class="max-w-[22rem] whitespace-normal break-words px-3 py-2.5 font-mono text-[11px] leading-snug" :title="it.path">{{ it.path }}</td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs" :title="it.client_ip || ''">{{ it.client_ip || '—' }}</td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-500" :title="it.tcp_peer || ''">{{ it.tcp_peer || '—' }}</td>
              <td class="max-w-[12rem] whitespace-normal break-words px-3 py-2.5 font-mono text-xs text-slate-300" :title="it.backend_name || ''">
                {{ it.backend_name || '—' }}
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs uppercase">{{ it.protocol || '—' }}</td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-xs">{{ it.country_code || '—' }}</td>
              <td class="max-w-[18rem] whitespace-normal break-all px-3 py-2.5 font-mono text-[11px] leading-snug text-slate-400" :title="it.upstream_base">
                {{ it.upstream_base }}
              </td>
              <td class="whitespace-nowrap px-3 py-2.5">
                <span class="inline-block max-w-[9rem] truncate align-top rounded-md bg-slate-800 px-2 py-0.5 text-xs text-slate-200" :title="labelOutcome(it.outcome)">
                  {{ labelOutcome(it.outcome) }}
                </span>
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

type Row = {
  id: number
  host: string
  method: string
  path: string
  client_ip: string
  tcp_peer?: string
  backend_name?: string
  protocol?: string
  country_code?: string
  user_agent?: string
  upstream_base: string
  outcome: string
  created_at: string
}

const items = ref<Row[]>([])
const err = ref('')
const busy = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(100)
const searchQ = ref('')
const hours = ref(168)
const filterOutcome = ref('')
const filterMethod = ref('')
const filterHost = ref('')
const filterClientIP = ref('')

function onSearch() {
  page.value = 1
  void load()
}

function onReset() {
  searchQ.value = ''
  hours.value = 168
  filterOutcome.value = ''
  filterMethod.value = ''
  filterHost.value = ''
  filterClientIP.value = ''
  page.value = 1
  void load()
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

function labelOutcome(o: string) {
  const m: Record<string, string> = {
    proxied: 'Проксировано',
    waf_block: 'Блок WAF',
    redirect: 'Редирект',
    malware_block: 'Антивирус',
  }
  return m[o] || o
}

function fmt(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const offset = (page.value - 1) * pageSize.value
    const q = new URLSearchParams({ limit: String(pageSize.value), offset: String(offset) })
    appendLogQueryBase(q, { q: searchQ.value, hours: hours.value })
    appendIfSet(q, 'outcome', filterOutcome.value)
    appendIfSet(q, 'method', filterMethod.value)
    appendIfSet(q, 'host', filterHost.value)
    appendIfSet(q, 'client_ip', filterClientIP.value)
    const data = await apiFetch<{ items: Row[]; total: number }>(apiUrl(`/proxy-access-logs?${q.toString()}`))
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
