<template>
  <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
    <h3 class="text-sm font-semibold text-white">Rate limit (система)</h3>
    <p class="mt-1 text-xs text-slate-500">
      Общий лимит для всего трафика через шлюз. На вкладке «Сайты» можно переопределить лимит для конкретного upstream или пути; если переопределение не задано — действует этот профиль.
    </p>
    <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label class="flex items-center gap-2 text-sm text-slate-300 sm:col-span-2">
        <input v-model="cfg.enabled" type="checkbox" class="rounded border-slate-600" />
        Включён
      </label>
      <label class="block text-xs text-slate-400">
        Запросов за окно
        <input v-model.number="cfg.requests_per_window" type="number" min="1" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-white" />
      </label>
      <label class="block text-xs text-slate-400">
        Окно (сек)
        <input v-model.number="cfg.window_sec" type="number" min="1" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-white" />
      </label>
      <label class="block text-xs text-slate-400 sm:col-span-2">
        Область счётчика
        <select v-model="cfg.scope" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200">
          <option value="ip">IP (все хосты)</option>
          <option value="ip_host">IP + Host</option>
          <option value="ip_path">IP + Host + Path</option>
          <option value="backend">IP + бэкенд + Path</option>
        </select>
      </label>
    </div>
    <button
      type="button"
      class="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
      :disabled="busy"
      @click="save"
    >
      Сохранить
    </button>
  </section>
</template>

<script setup lang="ts">
const { apiUrl, apiFetch } = useApi()

type RateLimitCfg = {
  enabled: boolean
  requests_per_window: number
  window_sec: number
  scope: string
}

const cfg = reactive<RateLimitCfg>({
  enabled: true,
  requests_per_window: 120,
  window_sec: 60,
  scope: 'ip_host',
})
const busy = ref(false)

async function load() {
  const data = await apiFetch<{ config: RateLimitCfg }>(apiUrl('/settings/rate-limit'))
  Object.assign(cfg, data.config || {})
}

async function save() {
  busy.value = true
  try {
    await apiFetch(apiUrl('/settings/rate-limit'), { method: 'PUT', body: { config: { ...cfg } } })
  } finally {
    busy.value = false
  }
}

onMounted(() => load())
defineExpose({ load })
</script>
