<template>
  <div class="space-y-6">
    <p v-if="errBanner" class="rounded-xl border border-rose-500/25 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
      {{ errBanner }}
    </p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">ИИ‑помощник</h2>
      <p class="mt-1 text-sm text-slate-400">
        Ответы формирует внешняя модель (OpenAI‑совместимый API). Ключ задаётся на сервере
        <span class="font-mono text-slate-300">policy-api</span>, в браузер не передаётся.
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
      <div class="mt-4 flex flex-wrap items-center gap-3">
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
          <span v-else class="text-amber-400">Ключ не задан — запросы недоступны</span>
          <span class="ml-2 font-mono text-xs text-slate-500">model={{ status.model }}</span>
        </span>
      </div>
    </section>

  <!-- Вопрос / диалог -->
    <section
      v-if="section === 'ask'"
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
    >
      <h3 class="text-base font-semibold text-white">Вопрос к ИИ</h3>
      <p class="mt-1 text-sm text-slate-400">Задайте вопрос по Fence, политикам, журналам или инциденту — ответ появится ниже.</p>

      <div class="mt-4 flex flex-wrap gap-4 text-sm">
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="askIncludeProxy" type="checkbox" class="rounded border-slate-600" />
          Журнал соединений
        </label>
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="askIncludeWaf" type="checkbox" class="rounded border-slate-600" />
          Журнал WAF
        </label>
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="askIncludePolicies" type="checkbox" class="rounded border-slate-600" />
          Политики и правила
        </label>
      </div>

      <div class="mt-4">
        <label class="block text-xs font-medium text-slate-500">Ваш вопрос</label>
        <textarea
          v-model="question"
          rows="4"
          class="mt-1 w-full resize-y rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600"
          placeholder="Например: почему блокируется IP 203.0.113.5 и что сделать безопасно?"
          @keydown.meta.enter.prevent="runAsk"
          @keydown.ctrl.enter.prevent="runAsk"
        />
      </div>

      <div class="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 px-5 py-2.5 text-sm font-medium text-white shadow-md disabled:opacity-50"
          :disabled="askBusy || !question.trim()"
          @click="runAsk"
        >
          {{ askBusy ? 'Отправка…' : 'Получить ответ' }}
        </button>
        <button
          v-if="conversation.length"
          type="button"
          class="rounded-lg border border-slate-600 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
          @click="clearConversation"
        >
          Очистить диалог
        </button>
      </div>

      <div v-if="conversation.length" class="mt-6 space-y-4">
        <div
          v-for="(turn, i) in conversation"
          :key="i"
          class="rounded-xl border border-slate-700/50 bg-slate-950/50 p-4"
        >
          <p class="text-xs font-medium text-violet-300/90">Вопрос</p>
          <p class="mt-1 text-sm text-slate-200">{{ turn.question }}</p>
          <p class="mt-4 text-xs font-medium text-emerald-300/90">Ответ · {{ turn.model }}</p>
          <pre class="mt-2 whitespace-pre-wrap break-words font-sans text-sm leading-relaxed text-slate-300">{{ turn.answer }}</pre>
        </div>
      </div>
    </section>

    <!-- Анализ -->
    <section
      v-else-if="section === 'analyze'"
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
    >
      <h3 class="text-base font-semibold text-white">Автоанализ журналов</h3>
      <p class="mt-1 text-sm text-slate-400">
        Модель получает срез данных из БД и даёт рекомендации по правилам и ложным срабатываниям.
      </p>

      <div class="mt-5 grid gap-4 sm:grid-cols-2">
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3">
          <input v-model="includeProxy" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Журнал соединений</span>
            <span class="mt-0.5 block text-xs text-slate-500">host, метод, путь, client_ip, исход</span>
          </span>
        </label>
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3">
          <input v-model="includeWaf" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Журнал срабатываний</span>
            <span class="mt-0.5 block text-xs text-slate-500">действие, политика, правило, IP</span>
          </span>
        </label>
        <label class="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-700/50 bg-slate-950/30 px-4 py-3 sm:col-span-2">
          <input v-model="includePolicies" type="checkbox" class="mt-1 rounded border-slate-600 bg-slate-900 text-violet-500" />
          <span>
            <span class="font-medium text-slate-200">Снимок политик и правил</span>
          </span>
        </label>
      </div>

      <div class="mt-4 grid gap-4 sm:grid-cols-2">
        <div>
          <label class="block text-xs font-medium text-slate-500">Строк журнала соединений</label>
          <input v-model.number="proxyLimit" type="number" min="1" max="100" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm" />
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-500">Строк журнала WAF</label>
          <input v-model.number="wafLimit" type="number" min="1" max="100" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm" />
        </div>
      </div>

      <div class="mt-4">
        <label class="block text-xs font-medium text-slate-500">Дополнительный контекст</label>
        <textarea v-model="extraContext" rows="3" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm" />
      </div>

      <button
        type="button"
        class="mt-5 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 px-5 py-2.5 text-sm font-medium text-white disabled:opacity-50"
        :disabled="analyzeBusy || (status != null && !status.configured)"
        @click="runAnalyze"
      >
        {{ analyzeBusy ? 'Анализ… (до 2–3 мин)' : 'Запустить анализ' }}
      </button>
      <p v-if="analyzeBusy" class="mt-2 text-xs text-slate-500">Запрос к модели {{ status?.model || '…' }} — подождите, не закрывайте вкладку.</p>
      <p v-if="analyzeError" class="mt-3 rounded-lg border border-rose-800/60 bg-rose-950/40 px-3 py-2 text-sm text-rose-200">{{ analyzeError }}</p>

      <div v-if="analysis" class="mt-6">
        <h4 class="text-sm font-medium text-slate-300">Ответ модели</h4>
        <pre class="mt-2 max-h-[min(70vh,900px)] overflow-auto whitespace-pre-wrap rounded-xl border border-slate-700/60 bg-slate-950/80 p-4 text-sm text-slate-200">{{ analysis }}</pre>
      </div>
    </section>

    <!-- Настройка -->
    <section
      v-else
      class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm"
    >
      <h3 class="text-base font-semibold text-white">Настройка на сервере</h3>
      <dl class="mt-4 space-y-3 text-sm">
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_API_KEY</dt>
          <dd class="mt-1 text-slate-400">Секретный ключ (обязательно).</dd>
        </div>
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_BASE_URL</dt>
          <dd class="mt-1 text-slate-400">База API, по умолчанию https://api.openai.com/v1</dd>
        </div>
        <div class="rounded-xl border border-slate-700/60 bg-slate-950/40 px-4 py-3">
          <dt class="font-mono text-teal-300/90">FENCE_AI_MODEL</dt>
          <dd class="mt-1 text-slate-400">Модель, по умолчанию gpt-4o-mini</dd>
        </div>
      </dl>
    </section>
  </div>
</template>

<script setup lang="ts">
const { apiUrl, apiFetch } = useApi()

function formatFetchError(e: unknown): string {
  if (e && typeof e === 'object') {
    const o = e as { data?: { error?: string }; message?: string }
    if (typeof o.data?.error === 'string') return o.data.error
    if (typeof o.message === 'string' && o.message.trim() !== '') return o.message
  }
  return e instanceof Error ? e.message : 'Ошибка запроса'
}

type SectionId = 'ask' | 'analyze' | 'setup'
const section = ref<SectionId>('ask')
const sections: { id: SectionId; label: string }[] = [
  { id: 'ask', label: 'Вопрос' },
  { id: 'analyze', label: 'Анализ журналов' },
  { id: 'setup', label: 'Настройка' },
]

type AiStatus = { configured: boolean; model: string; base_url: string }

const status = ref<AiStatus | null>(null)
const statusBusy = ref(false)
const errBanner = ref('')

const question = ref('')
const askIncludeProxy = ref(false)
const askIncludeWaf = ref(true)
const askIncludePolicies = ref(true)
const askBusy = ref(false)
const conversation = ref<{ question: string; answer: string; model: string }[]>([])

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
    status.value = await apiFetch<AiStatus>(apiUrl('/settings/ai'))
  } catch (e: unknown) {
    errBanner.value = formatFetchError(e)
    status.value = null
  } finally {
    statusBusy.value = false
  }
}

async function runAsk() {
  const q = question.value.trim()
  if (!q) return
  errBanner.value = ''
  askBusy.value = true
  try {
    const res = await apiFetch<{ answer: string; model: string }>(apiUrl('/ai/ask'), {
      method: 'POST',
      timeout: 180_000,
      body: {
        question: q,
        include_proxy_logs: askIncludeProxy.value,
        include_waf_logs: askIncludeWaf.value,
        include_policy_snapshot: askIncludePolicies.value,
        proxy_limit: 20,
        waf_limit: 20,
      },
    })
    conversation.value.push({ question: q, answer: res.answer, model: res.model })
    question.value = ''
  } catch (e: unknown) {
    errBanner.value = formatFetchError(e)
  } finally {
    askBusy.value = false
  }
}

function clearConversation() {
  conversation.value = []
}

const analyzeError = ref('')

async function runAnalyze() {
  errBanner.value = ''
  analyzeError.value = ''
  analysis.value = ''
  analyzeBusy.value = true
  try {
    if (status.value && !status.value.configured) {
      analyzeError.value = 'ИИ не настроен: задайте FENCE_AI_API_KEY для policy-api и перезапустите контейнер.'
      return
    }
    const res = await apiFetch<{ analysis: string; model: string }>(apiUrl('/ai/analyze'), {
      method: 'POST',
      timeout: 180_000,
      body: {
        include_proxy_logs: includeProxy.value,
        include_waf_logs: includeWaf.value,
        include_policy_snapshot: includePolicies.value,
        proxy_limit: proxyLimit.value,
        waf_limit: wafLimit.value,
        extra_context: extraContext.value.trim(),
      },
    })
    const text = (res.analysis || '').trim()
    if (!text) {
      analyzeError.value = 'Сервер вернул пустой текст. Проверьте модель и логи policy-api.'
      return
    }
    analysis.value = text
  } catch (e: unknown) {
    const msg = formatFetchError(e)
    analyzeError.value = msg
    errBanner.value = msg
  } finally {
    analyzeBusy.value = false
  }
}

onMounted(() => {
  loadStatus()
})
</script>
