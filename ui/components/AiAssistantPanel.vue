<template>
  <div class="space-y-6">
    <p v-if="errBanner" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
      {{ errBanner }}
    </p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">ИИ‑помощник для политик и журналов</h2>
      <p class="mt-1 text-sm text-slate-400">
        Отправляет на сервер выдержки из журналов соединений и срабатываний WAF и дергает внешнюю модель (OpenAI‑совместимый
        API). Ключ хранится только на стороне <span class="font-mono text-slate-300">policy-api</span>, в браузер не попадает.
      </p>
      <div class="mt-5 flex flex-wrap gap-2 rounded-2xl border border-white/10 bg-slate-900/40 p-2 shadow-inner shadow-black/15">
        <button
          v-for="s in sections"
          :key="s.id"
          type="button"
          class="rounded-xl px-3 py-2 text-sm font-medium transition-all duration-200 sm:px-4"
          :class="
            section === s.id
              ? 'bg-gradient-to-r from-violet-600/95 to-fuchsia-700 text-white shadow-md shadow-violet-950/35'
              : 'text-slate-400 hover:bg-slate-800/80 hover:text-white'
          "
          @click="section = s.id"
        >
          {{ s.label }}
        </button>
      </div>
    </section>

    <section
      v-if="section === 'setup'"
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
    >
      <h3 class="text-base font-semibold text-white">Настройка на сервере</h3>
      <p class="mt-2 text-sm text-slate-400">
        Задайте переменные окружения для контейнера или процесса <span class="font-mono text-slate-300">policy-api</span>,
        перезапустите сервис и обновите эту страницу.
      </p>
      <dl class="mt-4 space-y-3 text-sm">
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_API_KEY</dt>
          <dd class="mt-1 text-slate-400">Секретный ключ (обязательно для анализа).</dd>
        </div>
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_BASE_URL</dt>
          <dd class="mt-1 text-slate-400">
            База API, по умолчанию <span class="font-mono text-slate-300">https://api.openai.com/v1</span>. Подходит
            OpenAI‑совместимый прокси или локальный сервер.
          </dd>
        </div>
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_MODEL</dt>
          <dd class="mt-1 text-slate-400">Идентификатор модели, по умолчанию <span class="font-mono text-slate-300">gpt-4o-mini</span>.</dd>
        </div>
      </dl>
      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          class="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm text-slate-200 hover:bg-slate-700"
          :disabled="statusBusy"
          @click="loadStatus"
        >
          Проверить состояние
        </button>
        <span v-if="status" class="text-sm">
          <span v-if="status.configured" class="text-emerald-400">ИИ настроен</span>
          <span v-else class="text-amber-400">Ключ не задан — анализ недоступен</span>
          <span class="ml-2 font-mono text-xs text-slate-500">model={{ status.model }} · {{ status.base_url }}</span>
        </span>
      </div>
    </section>

    <section
      v-else
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
    >
      <h3 class="text-base font-semibold text-white">Задача анализа</h3>
      <p class="mt-1 text-sm text-slate-400">
        Модель получает срез данных из БД и отвечает рекомендациями по правилам, включению/отключению защиты и проверке на
        ложные срабатывания. Решения всё равно принимает оператор вручную в разделах «Политики» и «Логирование».
      </p>

      <div class="mt-5 grid gap-4 sm:grid-cols-2">
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3">
          <input v-model="includeProxy" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Журнал соединений</span>
            <span class="mt-0.5 block text-xs text-slate-500">host, метод, путь, client_ip, исход, страна, User-Agent</span>
          </span>
        </label>
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3">
          <input v-model="includeWaf" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Журнал срабатываний</span>
            <span class="mt-0.5 block text-xs text-slate-500">действие, политика, правило, IP, путь, details</span>
          </span>
        </label>
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3 sm:col-span-2">
          <input v-model="includePolicies" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Снимок политик и правил</span>
            <span class="mt-0.5 block text-xs text-slate-500">имена, UUID, режим, фрагменты condition_json</span>
          </span>
        </label>
      </div>

      <div class="mt-4 grid gap-4 sm:grid-cols-2">
        <div>
          <label class="block text-xs font-medium text-slate-500">Строк журнала соединений (макс. 100)</label>
          <input
            v-model.number="proxyLimit"
            type="number"
            min="1"
            max="100"
            class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100"
          />
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-500">Строк журнала WAF (макс. 100)</label>
          <input
            v-model.number="wafLimit"
            type="number"
            min="1"
            max="100"
            class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100"
          />
        </div>
      </div>

      <div class="mt-4">
        <label class="block text-xs font-medium text-slate-500">Дополнительный контекст (URL приложения, известные боты, окно обслуживания…)</label>
        <textarea
          v-model="extraContext"
          rows="4"
          class="mt-1 w-full resize-y rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600"
          placeholder="Необязательно. Помогает модели отличить ожидаемый трафик от атаки."
        />
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          class="rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 px-5 py-2.5 text-sm font-medium text-white shadow-md shadow-violet-950/30 hover:from-violet-500 hover:to-fuchsia-500 disabled:opacity-50"
          :disabled="analyzeBusy"
          @click="runAnalyze"
        >
          {{ analyzeBusy ? 'Анализ…' : 'Запустить анализ' }}
        </button>
      </div>

      <div v-if="analysis" class="mt-6">
        <h4 class="text-sm font-medium text-slate-300">Ответ модели</h4>
        <pre
          class="mt-2 max-h-[min(70vh,900px)] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-700/60 bg-slate-950/80 p-4 font-sans text-sm leading-relaxed text-slate-200"
        >{{ analysis }}</pre>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
const { apiUrl } = useApi()

function formatFetchError(e: unknown): string {
  if (e && typeof e === 'object') {
    const o = e as { data?: { error?: string }; message?: string }
    if (typeof o.data?.error === 'string') {
      return o.data.error
    }
    if (typeof o.message === 'string' && o.message.trim() !== '') {
      return o.message
    }
  }
  return e instanceof Error ? e.message : 'Ошибка запроса'
}

type SectionId = 'setup' | 'analyze'
const section = ref<SectionId>('analyze')
const sections: { id: SectionId; label: string }[] = [
  { id: 'analyze', label: 'Анализ' },
  { id: 'setup', label: 'Настройка' },
]

type AiStatus = { configured: boolean; model: string; base_url: string }

const status = ref<AiStatus | null>(null)
const statusBusy = ref(false)
const errBanner = ref('')

const includeProxy = ref(true)
const includeWaf = ref(true)
const includePolicies = ref(true)
const proxyLimit = ref(40)
const wafLimit = ref(40)
const extraContext = ref('')

const analyzeBusy = ref(false)
const analysis = ref('')

async function loadStatus() {
  errBanner.value = ''
  statusBusy.value = true
  try {
    status.value = await $fetch<AiStatus>(apiUrl('/api/v1/settings/ai'))
  } catch (e: unknown) {
    errBanner.value = formatFetchError(e)
    status.value = null
  } finally {
    statusBusy.value = false
  }
}

async function runAnalyze() {
  errBanner.value = ''
  analysis.value = ''
  analyzeBusy.value = true
  try {
    const res = await $fetch<{ analysis: string; model: string }>(apiUrl('/api/v1/ai/analyze'), {
      method: 'POST',
      body: {
        include_proxy_logs: includeProxy.value,
        include_waf_logs: includeWaf.value,
        include_policy_snapshot: includePolicies.value,
        proxy_limit: proxyLimit.value,
        waf_limit: wafLimit.value,
        extra_context: extraContext.value.trim(),
      },
    })
    analysis.value = res.analysis
  } catch (e: unknown) {
    errBanner.value = formatFetchError(e)
  } finally {
    analyzeBusy.value = false
  }
}

onMounted(() => {
  loadStatus()
})
</script>
