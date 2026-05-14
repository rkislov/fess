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
      <div class="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="button"
          class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
          :disabled="busy"
          @click="load"
        >
          Обновить
        </button>
      </div>
      <div class="mt-4 overflow-x-auto rounded-lg border border-slate-800/80">
        <table class="w-full table-fixed border-separate border-spacing-0 text-left text-sm">
          <colgroup>
            <col class="w-[11%]" />
            <col class="w-[12%]" />
            <col class="w-[6%]" />
            <col class="w-[18%]" />
            <col class="w-[8%]" />
            <col class="w-[8%]" />
            <col class="w-[9%]" />
            <col class="w-[5%]" />
            <col class="w-[5%]" />
            <col class="w-[13%]" />
            <col class="w-[5%]" />
          </colgroup>
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Время</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Host</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Метод</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Путь</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom" title="После LB, если настроен WAF_TRUSTED_PROXIES">Клиент</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom" title="TCP RemoteAddr (часто балансировщик)">TCP пир</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom" title="Имя строки бэкенда (первый по приоритету)">Бэкенд</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Протокол</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Страна</th>
              <th class="whitespace-nowrap px-2 py-2 pr-1 text-left align-bottom">Upstream URL</th>
              <th class="whitespace-nowrap px-2 py-2 text-left align-bottom">Итог</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!items.length && !busy">
              <td colspan="11" class="py-8 text-center text-slate-500">Нет данных — сделайте несколько запросов через шлюз и нажмите «Обновить»</td>
            </tr>
            <tr v-for="it in items" :key="it.id" class="border-b border-slate-800/80">
              <td class="whitespace-nowrap px-2 py-2 pr-1 align-top font-mono text-xs text-slate-400">{{ fmt(it.created_at) }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs" :title="it.host">{{ it.host || '—' }}</td>
              <td class="whitespace-nowrap px-2 py-2 pr-1 align-top">{{ it.method }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs" :title="it.path">{{ it.path }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs" :title="it.client_ip || ''">{{ it.client_ip || '—' }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs text-slate-500" :title="it.tcp_peer || ''">{{ it.tcp_peer || '—' }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs text-slate-300" :title="it.backend_name || ''">{{ it.backend_name || '—' }}</td>
              <td class="whitespace-nowrap px-2 py-2 pr-1 align-top font-mono text-xs uppercase">{{ it.protocol || '—' }}</td>
              <td class="whitespace-nowrap px-2 py-2 pr-1 align-top font-mono text-xs">{{ it.country_code || '—' }}</td>
              <td class="min-w-0 truncate px-2 py-2 pr-1 align-top font-mono text-xs" :title="it.upstream_base">{{ it.upstream_base }}</td>
              <td class="px-2 py-2 align-top">
                <span class="rounded-md bg-slate-800 px-2 py-0.5 text-xs text-slate-200">{{ labelOutcome(it.outcome) }}</span>
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
const { apiUrl } = useApi()

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
    const data = await $fetch<{ items: Row[]; total: number }>(apiUrl(`/proxy-access-logs?${q.toString()}`))
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
