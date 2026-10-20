<template>
  <div class="fixed inset-0 z-40 flex flex-col bg-slate-950/95 backdrop-blur-md">
    <header class="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-4 sm:px-6">
      <div>
        <h2 class="text-lg font-semibold text-white">Срабатывания WAF</h2>
        <p class="mt-0.5 text-sm text-slate-400">
          Полный журнал за период
          <span v-if="filterRule" class="font-mono text-slate-300"> · правило {{ shortId(filterRule) }}</span>
          <span v-if="filterAction" class="text-teal-300/90"> · {{ filterAction }}</span>
        </p>
      </div>
      <div class="flex min-w-[12rem] max-w-md flex-1 items-center gap-2">
        <input
          v-model="searchQ"
          type="search"
          placeholder="Поиск…"
          class="h-9 min-w-0 flex-1 rounded-lg border border-slate-600 bg-slate-800 px-3 text-sm text-white"
          @keydown.enter.prevent="onSearch"
        />
        <select
          v-model.number="hours"
          class="h-9 shrink-0 rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm text-white"
        >
          <option :value="0">Всё</option>
          <option :value="6">6 ч</option>
          <option :value="24">24 ч</option>
          <option :value="72">3 суток</option>
          <option :value="168">7 суток</option>
        </select>
        <button
          type="button"
          class="h-9 shrink-0 rounded-lg bg-teal-700/90 px-3 text-sm text-white hover:bg-teal-600"
          :disabled="busy"
          @click="onSearch"
        >
          Найти
        </button>
        <button
          type="button"
          class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700"
          @click="emit('close')"
        >
          Закрыть
        </button>
      </div>
    </header>

    <p v-if="err" class="mx-4 mt-3 rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200 sm:mx-6">
      {{ err }}
    </p>

    <div class="min-h-0 flex-1 overflow-auto px-4 py-4 sm:px-6">
      <table class="w-full text-left text-sm">
        <thead class="sticky top-0 z-10 bg-slate-950/90 text-slate-500 backdrop-blur">
          <tr class="border-b border-slate-700">
            <th class="py-2 pr-3">Время</th>
            <th class="py-2 pr-3">Хост / сайт</th>
            <th class="py-2 pr-3">Правило</th>
            <th class="py-2 pr-3">Действие</th>
            <th class="py-2 pr-3">IP</th>
            <th class="py-2">Запрос</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!items.length && !busy">
            <td colspan="6" class="py-10 text-center text-slate-500">Нет записей за период</td>
          </tr>
          <tr
            v-for="it in items"
            :key="it.id"
            class="cursor-pointer border-b border-slate-800/80 transition hover:bg-slate-800/50"
            @click="openDetail(it.id)"
          >
            <td class="whitespace-nowrap py-2.5 pr-3 font-mono text-xs text-slate-400">{{ fmt(it.created_at) }}</td>
            <td class="max-w-[140px] truncate py-2.5 pr-3 text-slate-200" :title="it.host">{{ it.host || '—' }}</td>
            <td class="max-w-[120px] truncate py-2.5 pr-3 font-mono text-xs" :title="it.rule_id">{{ shortId(it.rule_id) || '—' }}</td>
            <td class="py-2.5 pr-3">
              <span class="rounded-md bg-slate-800 px-2 py-0.5 text-xs">{{ it.action }}</span>
            </td>
            <td class="whitespace-nowrap py-2.5 pr-3 font-mono text-xs">{{ it.source_ip || '—' }}</td>
            <td class="max-w-[200px] truncate py-2.5 font-mono text-xs" :title="it.method + ' ' + it.path">
              {{ it.method }} {{ it.path }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <footer class="shrink-0 border-t border-white/10 px-4 py-3 sm:px-6">
      <LogPaginationBar
        :total="total"
        :page="page"
        :page-size="pageSize"
        :busy="busy"
        @update:page="onPage"
        @update:page-size="onPageSize"
      />
    </footer>
  </div>
</template>

<script setup lang="ts">
const props = defineProps<{
  initialHours?: number
  ruleId?: string
  action?: string
}>()

const emit = defineEmits<{
  close: []
  openEvent: [id: number]
}>()

const { apiUrl, apiFetch } = useApi()

type Row = {
  id: number
  rule_id: string
  action: string
  host: string
  source_ip: string
  method: string
  path: string
  created_at: string
}

const hours = ref(props.initialHours ?? 24)
const searchQ = ref('')
const filterRule = ref(props.ruleId ?? '')
const filterAction = ref(props.action ?? '')

function onSearch() {
  page.value = 1
  void reload()
}
const items = ref<Row[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(50)
const busy = ref(false)
const err = ref('')

function shortId(id: string) {
  if (!id) return ''
  return id.length > 12 ? `${id.slice(0, 8)}…` : id
}

function fmt(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}

function openDetail(id: number) {
  emit('openEvent', id)
}

async function reload() {
  busy.value = true
  err.value = ''
  try {
    const q = new URLSearchParams({
      hours: String(hours.value),
      limit: String(pageSize.value),
      offset: String((page.value - 1) * pageSize.value),
    })
    appendLogQueryBase(q, { q: searchQ.value, hours: hours.value })
    if (filterRule.value) q.set('rule_id', filterRule.value)
    if (filterAction.value) q.set('action', filterAction.value)
    const data = await apiFetch<{ items: Row[]; total: number }>(apiUrl(`/waf-log-events?${q}`))
    items.value = data.items || []
    total.value = data.total ?? 0
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

function onPage(p: number) {
  page.value = p
  void reload()
}

function onPageSize(n: number) {
  pageSize.value = n
  page.value = 1
  void reload()
}

onMounted(() => {
  void reload()
})

watch(
  () => [props.initialHours, props.ruleId, props.action] as const,
  ([h, r, a]) => {
    if (h != null) hours.value = h
    filterRule.value = r ?? ''
    filterAction.value = a ?? ''
    page.value = 1
    void reload()
  },
)
</script>
