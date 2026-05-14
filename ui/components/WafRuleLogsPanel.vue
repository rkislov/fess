<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Срабатывания правил WAF</h2>
      <p class="mt-1 text-sm text-slate-400">
        Записи из шлюза: сработала конкретная политика/правило, блокировка вредоносного ПО и эффективное действие.
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
            <tr v-for="(it, idx) in items" :key="idx" class="border-b border-slate-800/80">
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
    </section>
  </div>
</template>

<script setup lang="ts">
const { apiUrl } = useApi()

type Row = {
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

function fmt(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}

function reason(it: Row) {
  const d = it.details
  if (d && typeof d === 'object' && 'reason' in d && typeof (d as { reason?: string }).reason === 'string') {
    return (d as { reason: string }).reason
  }
  return '—'
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const data = await $fetch<{ items: Row[] }>(apiUrl('/logs'))
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
