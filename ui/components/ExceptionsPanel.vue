<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Исключения по IP/CIDR</h3>
      <p class="mt-1 text-xs text-slate-500">
        Глобальный обход: WAF, Q-feed, защита от ботов и rate limit не применяются к перечисленным адресам. Создаются здесь, из карточки
        события WAF или при разблокировке IP.
      </p>
      <p class="mt-2 text-xs text-slate-600">
        Ограничения по IP на отдельных путях бэкенда настраиваются в разделе «Сайты».
      </p>

      <form class="mt-5 grid gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4 sm:grid-cols-2" @submit.prevent="create">
        <label class="block text-xs text-slate-500 sm:col-span-2">
          IP или CIDR
          <input
            v-model="form.cidr"
            required
            placeholder="203.0.113.42 или 10.0.0.0/8"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm"
          />
        </label>
        <label class="block text-xs text-slate-500 sm:col-span-2">
          Комментарий
          <input v-model="form.comment" placeholder="офис, мониторинг…" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" />
        </label>
        <label class="block text-xs text-slate-500">
          Срок (часов, 0 = бессрочно)
          <input v-model.number="form.ttl_hours" type="number" min="0" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" />
        </label>
        <div class="flex items-end">
          <button
            type="submit"
            class="w-full rounded-lg bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-600 disabled:opacity-50"
            :disabled="busy"
          >
            Добавить исключение
          </button>
        </div>
      </form>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h3 class="text-sm font-semibold text-white">Список исключений</h3>
        <button type="button" class="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700" :disabled="busy" @click="load">
          Обновить
        </button>
      </div>

      <p v-if="!items.length && !busy" class="mt-4 text-sm text-slate-500">Нет записей — добавьте IP/CIDR выше.</p>

      <ul class="mt-4 space-y-2">
        <li
          v-for="row in items"
          :key="row.cidr"
          class="rounded-lg border border-slate-800 bg-slate-950/60 px-4 py-3 text-sm"
        >
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div class="min-w-0">
              <span class="font-mono text-base text-teal-200">{{ row.cidr }}</span>
              <p v-if="row.comment" class="mt-1 text-xs text-slate-400">{{ row.comment }}</p>
              <div class="mt-2 flex flex-wrap gap-1">
                <span v-for="s in row.scopes" :key="s" class="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">{{ s }}</span>
              </div>
            </div>
            <button
              type="button"
              class="shrink-0 rounded border border-rose-800/60 px-2 py-1 text-xs text-rose-300 hover:bg-rose-950/40"
              :disabled="busy"
              @click="remove(row.cidr)"
            >
              Удалить
            </button>
          </div>
          <dl class="mt-2 grid gap-1 text-[10px] text-slate-500 sm:grid-cols-2">
            <div>
              <dt class="inline text-slate-600">Создано: </dt>
              <dd class="inline font-mono">{{ fmtTs(row.created_at) }}</dd>
            </div>
            <div>
              <dt class="inline text-slate-600">Истекает: </dt>
              <dd class="inline font-mono">{{ row.expires_at ? fmtTs(row.expires_at) : 'бессрочно' }}</dd>
            </div>
            <div v-if="row.source_waf_log_id" class="sm:col-span-2">
              <dt class="inline text-slate-600">Из события WAF: </dt>
              <dd class="inline font-mono">#{{ row.source_waf_log_id }}</dd>
            </div>
          </dl>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

type BypassRow = {
  cidr: string
  comment: string
  source_waf_log_id?: number
  expires_at?: string
  created_at: string
  scopes: string[]
}

const items = ref<BypassRow[]>([])
const busy = ref(false)
const err = ref('')
const ok = ref('')

const form = reactive({
  cidr: '',
  comment: '',
  ttl_hours: 168,
})

function fmtTs(s?: string) {
  if (!s) return '—'
  try {
    return new Date(s).toLocaleString()
  } catch {
    return s
  }
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
  }, 4000)
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const data = await apiFetch<{ items: BypassRow[] }>(apiUrl('/ip-bypass'))
    items.value = data.items || []
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function create() {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/ip-bypass'), {
      method: 'POST',
      body: {
        cidr: form.cidr.trim(),
        comment: form.comment.trim(),
        ttl_hours: form.ttl_hours,
      },
    })
    form.cidr = ''
    form.comment = ''
    await load()
    flashOk('Исключение добавлено')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function remove(cidr: string) {
  if (!confirm(`Удалить исключение для ${cidr}?`)) return
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl('/ip-bypass'), { method: 'DELETE', body: { cidr } })
    await load()
    flashOk('Исключение удалено')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  void load()
})

defineExpose({ reload: load })
</script>
