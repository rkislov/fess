<template>
  <div class="space-y-6">
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Интеграция с LLM</h3>
      <p class="mt-1 text-xs text-slate-500">
        Параметры из этой формы сохраняются в БД и <strong class="text-slate-400">переопределяют</strong> переменные
        окружения <span class="font-mono">FENCE_AI_*</span> в docker-compose (пустое поле в БД — берётся значение из env).
      </p>

      <div v-if="effective" class="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
          <span class="text-slate-500">Сейчас используется</span>
          <p class="mt-1 font-mono text-teal-200/90">{{ effective.base_url }}</p>
          <p class="font-mono text-slate-400">{{ effective.model }}</p>
          <p class="mt-1 text-slate-500">таймаут {{ effective.http_timeout_sec }} с · {{ configured ? 'ключ задан' : 'ключ не задан' }}</p>
        </div>
        <div v-if="envDefaults" class="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
          <span class="text-slate-500">Значения из docker-compose (env)</span>
          <p class="mt-1 font-mono text-slate-400">{{ envDefaults.base_url || '—' }}</p>
          <p class="font-mono text-slate-400">{{ envDefaults.model || '—' }}</p>
          <p class="mt-1 text-slate-500">таймаут {{ envDefaults.http_timeout_sec || '—' }} с</p>
        </div>
      </div>

      <form class="mt-6 space-y-4" @submit.prevent="save">
        <label class="flex items-center gap-2 text-sm text-slate-300">
          <input v-model="form.enabled" type="checkbox" class="rounded border-slate-600" />
          ИИ включён
        </label>
        <label class="block text-xs text-slate-500">
          Base URL (OpenAI-compatible)
          <input
            v-model="form.base_url"
            placeholder="http://10.0.156.40/v1"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
          />
        </label>
        <label class="block text-xs text-slate-500">
          Модель
          <input v-model="form.model" placeholder="gpt-oss-20b" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm" />
        </label>
        <label class="block text-xs text-slate-500">
          API key / token
          <input
            v-model="form.api_key"
            type="password"
            autocomplete="new-password"
            :placeholder="apiKeySet ? 'Оставьте пустым, чтобы не менять' : 'sk-… или gpustack_…'"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
          />
        </label>
        <label class="block text-xs text-slate-500">
          Таймаут HTTP, сек (30–1800; 0 в БД = из env)
          <input
            v-model.number="form.http_timeout_sec"
            type="number"
            min="0"
            max="1800"
            step="30"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          />
        </label>
        <button
          type="submit"
          class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          :disabled="busy"
        >
          Сохранить настройки ИИ
        </button>
      </form>
    </section>
  </div>
</template>

<script setup lang="ts">
const { apiUrl, apiFetch } = useApi()

type AiSettingsForm = {
  enabled: boolean
  base_url: string
  model: string
  api_key: string
  http_timeout_sec: number
}

type AiSettingsResp = AiSettingsForm & {
  api_key_set?: boolean
  configured?: boolean
  env_defaults?: AiSettingsForm
  effective?: Omit<AiSettingsForm, 'api_key'>
}

const busy = ref(false)
const apiKeySet = ref(false)
const configured = ref(false)
const envDefaults = ref<AiSettingsForm | null>(null)
const effective = ref<Omit<AiSettingsForm, 'api_key'> | null>(null)

const form = reactive<AiSettingsForm>({
  enabled: true,
  base_url: '',
  model: '',
  api_key: '',
  http_timeout_sec: 0,
})

async function load() {
  busy.value = true
  try {
    const data = await apiFetch<AiSettingsResp>(apiUrl('/settings/ai'))
    apiKeySet.value = !!data.api_key_set
    configured.value = !!data.configured
    envDefaults.value = data.env_defaults ?? null
    effective.value = data.effective ?? null
    const eff = data.effective
    form.enabled = data.enabled ?? eff?.enabled ?? true
    form.base_url = data.base_url || eff?.base_url || ''
    form.model = data.model || eff?.model || ''
    form.http_timeout_sec = data.http_timeout_sec || eff?.http_timeout_sec || 0
    form.api_key = ''
  } finally {
    busy.value = false
  }
}

async function save() {
  busy.value = true
  try {
    const data = await apiFetch<AiSettingsResp>(apiUrl('/settings/ai'), {
      method: 'PUT',
      body: {
        enabled: form.enabled,
        base_url: form.base_url.trim(),
        model: form.model.trim(),
        api_key: form.api_key,
        http_timeout_sec: form.http_timeout_sec,
      },
    })
    apiKeySet.value = !!data.api_key_set
    configured.value = !!data.configured
    envDefaults.value = data.env_defaults ?? null
    effective.value = data.effective ?? null
    form.api_key = ''
  } finally {
    busy.value = false
  }
}

defineExpose({ load })

onMounted(() => {
  void load()
})
</script>
