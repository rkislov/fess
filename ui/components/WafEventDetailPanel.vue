<template>
  <div class="fixed inset-0 z-40 flex flex-col bg-slate-950/95 backdrop-blur-md">
    <header class="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-4 sm:px-6">
      <div>
        <h2 class="text-lg font-semibold text-white">Срабатывание #{{ eventId }}</h2>
        <p v-if="detail" class="mt-0.5 text-sm text-slate-400">{{ fmt(detail.created_at) }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700"
          @click="emit('back')"
        >
          ← К списку
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
    <p v-if="actionMsg" class="mx-4 mt-3 rounded-xl border border-emerald-500/25 bg-emerald-950/30 px-4 py-3 text-sm text-emerald-200 sm:mx-6">
      {{ actionMsg }}
    </p>

    <div v-if="busy && !detail" class="flex flex-1 items-center justify-center text-slate-500">Загрузка…</div>

    <div v-else-if="detail" class="min-h-0 flex-1 overflow-auto px-4 py-6 sm:px-6">
      <div class="mx-auto max-w-3xl space-y-6">
        <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
          <h3 class="text-sm font-medium text-slate-300">Запрос</h3>
          <dl class="mt-3 grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt class="text-xs text-slate-500">Виртуальный хост</dt>
              <dd class="mt-0.5 font-mono text-slate-200">{{ detail.virtual_host || '—' }}</dd>
            </div>
            <div>
              <dt class="text-xs text-slate-500">Источник (IP)</dt>
              <dd class="mt-0.5 font-mono text-slate-200">{{ detail.source_ip || '—' }}</dd>
              <p v-if="detail.unblock?.bypass_active" class="mt-1 text-xs text-emerald-400/90">
                IP в списке обхода ({{ detail.unblock.bypass_cidr || detail.source_ip }})
              </p>
              <p v-else-if="detail.unblock?.in_threat_feed" class="mt-1 text-xs text-amber-300/90">
                IP есть в блоклисте threat feed
              </p>
            </div>
            <div class="sm:col-span-2">
              <dt class="text-xs text-slate-500">Запрос</dt>
              <dd class="mt-0.5 font-mono text-slate-200">{{ detail.method }} {{ detail.path }}</dd>
            </div>
            <div>
              <dt class="text-xs text-slate-500">Записанное действие</dt>
              <dd class="mt-0.5">
                <span class="rounded-md bg-slate-800 px-2 py-0.5 text-xs text-teal-300/90">{{ detail.action }}</span>
              </dd>
            </div>
          </dl>
        </section>

        <section v-if="detail.matching_sites?.length" class="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
          <h3 class="text-sm font-medium text-slate-300">Сайты Fence</h3>
          <ul class="mt-2 space-y-2 text-sm">
            <li
              v-for="s in detail.matching_sites"
              :key="s.id"
              class="rounded-lg bg-slate-800/60 px-3 py-2"
            >
              <span class="font-medium text-slate-200">{{ s.name }}</span>
              <span class="ml-2 font-mono text-xs text-slate-400">{{ s.host_pattern }}</span>
            </li>
          </ul>
        </section>

        <section
          v-if="detail.unblock?.can_unblock"
          class="rounded-2xl border border-teal-500/25 bg-teal-950/20 p-5"
        >
          <h3 class="text-sm font-medium text-teal-100">Разблокировка IP</h3>
          <p v-if="detail.unblock?.unblock_hint" class="mt-2 text-xs text-slate-400">{{ detail.unblock.unblock_hint }}</p>
          <label
            v-if="detail.unblock?.remove_from_feed"
            class="mt-3 flex items-center gap-2 text-sm text-slate-300"
          >
            <input v-model="removeFromThreatFeed" type="checkbox" class="rounded border-slate-600" />
            Удалить IP из блоклиста threat feed (Q-feed)
          </label>
          <label class="mt-3 block text-xs text-slate-500">
            Срок обхода, часов (по умолчанию 168 = 7 дней, 0 = без срока)
            <input
              v-model.number="unblockTTLHours"
              type="number"
              min="0"
              class="mt-1 w-28 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200"
            />
          </label>
          <button
            type="button"
            class="mt-4 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
            :disabled="unblockBusy || detail.unblock?.bypass_active"
            @click="unblockIP"
          >
            {{ detail.unblock?.bypass_active ? 'IP уже в обходе' : 'Разблокировать IP' }}
          </button>
        </section>

        <section v-if="detail.rule || detail.policy" class="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
          <h3 class="text-sm font-medium text-slate-300">Правило и политика</h3>
          <dl class="mt-3 space-y-2 text-sm">
            <div v-if="detail.policy">
              <dt class="text-xs text-slate-500">Политика</dt>
              <dd class="text-slate-200">
                {{ detail.policy.name }}
                <span class="font-mono text-xs text-slate-500">({{ detail.policy.mode }})</span>
                <span v-if="!detail.policy.enabled" class="ml-2 text-amber-400">выкл.</span>
              </dd>
            </div>
            <div v-if="detail.rule">
              <dt class="text-xs text-slate-500">Правило</dt>
              <dd class="text-slate-200">
                {{ detail.rule.name }}
                <span class="font-mono text-xs text-slate-500">action={{ detail.rule.action }}</span>
                <span v-if="!detail.rule.enabled" class="ml-2 text-amber-400">выключено</span>
                <span v-else class="ml-2 text-emerald-400/80">включено</span>
              </dd>
            </div>
          </dl>
          <div v-if="detail.rule" class="mt-4 flex flex-wrap gap-2">
            <button
              v-if="!detail.rule.enabled"
              type="button"
              class="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
              :disabled="ruleBusy"
              @click="ruleAction('enable')"
            >
              Включить правило
            </button>
            <button
              v-if="detail.rule.enabled"
              type="button"
              class="rounded-lg bg-slate-700 px-4 py-2 text-sm font-medium text-white hover:bg-slate-600 disabled:opacity-50"
              :disabled="ruleBusy"
              @click="ruleAction('disable')"
            >
              Отключить правило
            </button>
            <button
              v-if="detail.rule.enabled && detail.rule.action !== 'block'"
              type="button"
              class="rounded-lg bg-rose-700 px-4 py-2 text-sm font-medium text-white hover:bg-rose-600 disabled:opacity-50"
              :disabled="ruleBusy"
              @click="ruleAction('block')"
            >
              Включить блокировку
            </button>
            <button
              v-if="detail.rule.enabled && detail.rule.action !== 'log'"
              type="button"
              class="rounded-lg border border-amber-600/50 bg-amber-950/40 px-4 py-2 text-sm text-amber-100 hover:bg-amber-900/40 disabled:opacity-50"
              :disabled="ruleBusy"
              @click="ruleAction('log_only')"
            >
              Только логировать
            </button>
          </div>
          <p v-else-if="detail.action === 'malware_block'" class="mt-3 text-xs text-slate-500">
            Блокировка антивирусом — управление через раздел «Антивирус».
          </p>
        </section>

        <section class="rounded-2xl border border-violet-500/20 bg-slate-900/50 p-5">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h3 class="text-sm font-medium text-violet-200/90">Анализ ИИ</h3>
            <button
              type="button"
              class="rounded-lg border border-violet-600/40 bg-violet-950/50 px-3 py-1.5 text-xs text-violet-100 hover:bg-violet-900/40 disabled:opacity-50"
              :disabled="aiBusy || !aiConfigured"
              :title="aiConfigured ? '' : 'Задайте FENCE_AI_API_KEY на policy-api'"
              @click="runAi"
            >
              {{ aiBusy ? 'Анализ…' : detail.ai_analysis ? 'Обновить анализ' : 'Запросить анализ' }}
            </button>
          </div>
          <pre
            v-if="detail.ai_analysis"
            class="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-700/60 bg-slate-950/80 p-4 text-sm leading-relaxed text-slate-200"
          >{{ detail.ai_analysis }}</pre>
          <p v-else-if="!aiConfigured" class="mt-3 text-sm text-slate-500">ИИ не настроен на сервере.</p>
          <p v-else class="mt-3 text-sm text-slate-500">Нажмите «Запросить анализ» для оценки ложного срабатывания и рекомендаций.</p>
        </section>

        <section v-if="detailsText" class="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
          <h3 class="text-sm font-medium text-slate-300">Детали (JSON)</h3>
          <pre class="mt-2 overflow-auto rounded-lg bg-slate-950/80 p-3 font-mono text-xs text-slate-400">{{ detailsText }}</pre>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const props = defineProps<{ eventId: number }>()
const emit = defineEmits<{ back: []; close: [] }>()

const { apiUrl, apiFetch } = useApi()

type SiteBrief = { id: string; name: string; host_pattern: string; policy_id?: string }
type RuleBrief = { id: string; name: string; action: string; enabled: boolean; policy_id: string }
type PolicyBrief = { id: string; name: string; mode: string; enabled: boolean }

type UnblockCtx = {
  can_unblock?: boolean
  bypass_active?: boolean
  bypass_cidr?: string
  in_threat_feed?: boolean
  remove_from_feed?: boolean
  unblock_hint?: string
}

type Detail = {
  id: number
  created_at: string
  virtual_host: string
  source_ip: string
  method: string
  path: string
  action: string
  rule?: RuleBrief | null
  policy?: PolicyBrief | null
  matching_sites?: SiteBrief[]
  details?: Record<string, unknown>
  ai_analysis?: string
  unblock?: UnblockCtx
}

const detail = ref<Detail | null>(null)
const busy = ref(false)
const ruleBusy = ref(false)
const unblockBusy = ref(false)
const removeFromThreatFeed = ref(false)
const unblockTTLHours = ref(168)
const aiBusy = ref(false)
const err = ref('')
const actionMsg = ref('')
const aiConfigured = ref(false)

const detailsText = computed(() => {
  if (!detail.value?.details) return ''
  try {
    return JSON.stringify(detail.value.details, null, 2)
  } catch {
    return ''
  }
})

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
    detail.value = await $fetch<Detail>(apiUrl(`/waf-log-events/${props.eventId}`))
    removeFromThreatFeed.value = !!detail.value?.unblock?.in_threat_feed
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
    detail.value = null
  } finally {
    busy.value = false
  }
}

async function loadAiStatus() {
  try {
    const s = await $fetch<{ configured: boolean }>(apiUrl('/settings/ai'))
    aiConfigured.value = !!s.configured
  } catch {
    aiConfigured.value = false
  }
}

async function runAi() {
  if (!aiConfigured.value) return
  aiBusy.value = true
  err.value = ''
  try {
    const res = await $fetch<{ analysis: string }>(apiUrl(`/waf-log-events/${props.eventId}/ai-review`), {
      method: 'POST',
    })
    if (detail.value) {
      detail.value = { ...detail.value, ai_analysis: res.analysis }
    }
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    aiBusy.value = false
  }
}

async function unblockIP() {
  if (!detail.value?.unblock?.can_unblock || detail.value.unblock?.bypass_active) return
  unblockBusy.value = true
  actionMsg.value = ''
  err.value = ''
  try {
    const res = await $fetch<{
      ok: boolean
      bypass_cidr: string
      removed_from_threat_feed: boolean
      cleared_bot_rate_limit: boolean
    }>(apiUrl(`/waf-log-events/${props.eventId}/unblock`), {
      method: 'POST',
      body: {
        remove_from_threat_feed: removeFromThreatFeed.value,
        ttl_hours: unblockTTLHours.value > 0 ? unblockTTLHours.value : 0,
      },
    })
    const parts = [`IP ${res.bypass_cidr} добавлен в обход`]
    if (res.removed_from_threat_feed) parts.push('удалён из threat feed')
    if (res.cleared_bot_rate_limit) parts.push('сброшен rate limit')
    actionMsg.value = parts.join('; ') + '.'
    await load()
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    unblockBusy.value = false
  }
}

async function ruleAction(action: 'enable' | 'disable' | 'log_only' | 'block') {
  if (!detail.value?.rule?.id) return
  ruleBusy.value = true
  actionMsg.value = ''
  err.value = ''
  try {
    await apiFetch(apiUrl(`/rules/${detail.value.rule.id}/quick-action`), {
      method: 'POST',
      body: { action },
    })
    actionMsg.value =
      action === 'enable'
        ? 'Правило включено и политика опубликована на шлюз.'
        : action === 'disable'
          ? 'Правило отключено и политика опубликована.'
          : action === 'block'
            ? 'Правило переведено в режим block и политика опубликована.'
            : 'Правило переведено в режим «только log» и политика опубликована.'
    await load()
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    ruleBusy.value = false
  }
}

watch(
  () => props.eventId,
  () => {
    void load()
  },
)

onMounted(() => {
  void load()
  void loadAiStatus()
})
</script>
