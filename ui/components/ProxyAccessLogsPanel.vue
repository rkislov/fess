<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Соединения к сайтам</h2>
      <p class="mt-1 text-sm text-slate-400">
        Запросы через WAF: виртуальный хост, upstream из маршрутизации и итог (прокси, блок WAF, редирект, антивирус).
      </p>
      <div class="mt-4">
        <button
          type="button"
          class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
          :disabled="busy"
          @click="load"
        >
          Обновить
        </button>
      </div>
      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="py-2 pr-3">Время</th>
              <th class="py-2 pr-3">Host</th>
              <th class="py-2 pr-3">Метод</th>
              <th class="py-2 pr-3">Путь</th>
              <th class="py-2 pr-3">Клиент</th>
              <th class="py-2 pr-3">Протокол</th>
              <th class="py-2 pr-3">Страна</th>
              <th class="py-2 pr-3">Upstream</th>
              <th class="py-2">Итог</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!items.length && !busy">
              <td colspan="9" class="py-8 text-center text-slate-500">Нет данных — сделайте несколько запросов через шлюз и нажмите «Обновить»</td>
            </tr>
            <tr v-for="it in items" :key="it.id" class="border-b border-slate-800/80">
              <td class="whitespace-nowrap py-2 pr-3 font-mono text-xs text-slate-400">{{ fmt(it.created_at) }}</td>
              <td class="py-2 pr-3 font-mono text-xs">{{ it.host }}</td>
              <td class="py-2 pr-3">{{ it.method }}</td>
              <td class="max-w-[200px] truncate py-2 pr-3 font-mono text-xs" :title="it.path">{{ it.path }}</td>
              <td class="py-2 pr-3 font-mono text-xs">{{ it.client_ip }}</td>
              <td class="py-2 pr-3 font-mono text-xs uppercase">{{ it.protocol || '—' }}</td>
              <td class="py-2 pr-3 font-mono text-xs">{{ it.country_code || '—' }}</td>
              <td class="max-w-[220px] truncate py-2 pr-3 font-mono text-xs" :title="it.upstream_base">{{ it.upstream_base }}</td>
              <td class="py-2">
                <span class="rounded-md bg-slate-800 px-2 py-0.5 text-xs text-slate-200">{{ labelOutcome(it.outcome) }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
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
  protocol?: string
  country_code?: string
  upstream_base: string
  outcome: string
  created_at: string
}

const items = ref<Row[]>([])
const err = ref('')
const busy = ref(false)

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
    const data = await $fetch<{ items: Row[] }>(apiUrl('/proxy-access-logs'))
    items.value = data.items || []
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => load())
</script>
