<template>
  <div v-if="!ready" class="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400">
    <div class="flex flex-col items-center gap-3">
      <div
        class="h-10 w-10 animate-spin rounded-full border-2 border-teal-500/30 border-t-teal-400"
        aria-hidden="true"
      />
      <p class="text-sm">Загрузка…</p>
    </div>
  </div>

  <LoginScreen v-else-if="!authed" />

  <div v-else class="min-h-screen bg-gradient-to-b from-slate-950 via-slate-950 to-slate-900 text-slate-100 antialiased">
    <header
      class="sticky top-0 z-20 border-b border-white/5 bg-slate-950/85 px-4 py-3 backdrop-blur-md sm:px-6 sm:py-4"
    >
      <div class="mx-auto flex max-w-6xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <div
            class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-teal-400/90 to-indigo-600 text-lg shadow-md"
            aria-hidden="true"
          >
            🛡️
          </div>
          <div>
            <h1 class="text-lg font-semibold tracking-tight text-white sm:text-xl">Fence — панель управления</h1>
            <p class="mt-0.5 text-xs text-slate-400 sm:text-sm">
              Журналы, антивирус, политики и сайты — без перезапуска шлюза
            </p>
          </div>
        </div>
        <button
          type="button"
          class="self-start rounded-lg border border-slate-600/80 bg-slate-800/60 px-3 py-2 text-xs font-medium text-slate-200 transition hover:border-slate-500 hover:bg-slate-800 sm:self-center"
          @click="onLogout"
        >
          Выйти
        </button>
      </div>
    </header>

    <nav class="border-b border-white/5 bg-slate-900/40 px-4 py-3 sm:px-6">
      <div class="mx-auto max-w-6xl overflow-x-auto pb-1">
        <div class="flex min-w-max flex-wrap gap-2">
          <button
            v-for="t in tabs"
            :key="t.id"
            type="button"
            class="rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200 sm:px-4"
            :class="
              tab === t.id
                ? 'bg-gradient-to-r from-teal-500 to-emerald-600 text-white shadow-md shadow-teal-900/25'
                : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white'
            "
            @click="tab = t.id"
          >
            <span class="mr-1.5 opacity-80" aria-hidden="true">{{ t.icon }}</span>
            {{ t.label }}
          </button>
        </div>
      </div>
    </nav>

    <main class="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
      <DashboardPanel v-if="tab === 'dashboard'" />
      <SitesPanel v-else-if="tab === 'sites'" />
      <PoliciesPanel v-else-if="tab === 'policies'" />
      <MalwarePanel v-else-if="tab === 'antivirus'" />
      <ThreatFeedPanel v-else-if="tab === 'qfeed'" />
      <BotProtectionPanel v-else-if="tab === 'bots'" />
      <LoggingPanel v-else-if="tab === 'logging'" />
      <AiAssistantPanel v-else-if="tab === 'ai'" />
      <SettingsPanel v-else-if="tab === 'settings'" />
    </main>

    <WafEventsExplorerPanel
      v-if="hashView === 'waf-events'"
      :initial-hours="eventsParams.hours"
      :rule-id="eventsParams.rule_id"
      :action="eventsParams.action"
      @close="closeOverlay"
      @open-event="onOpenWafEvent"
    />
    <WafEventDetailPanel
      v-else-if="hashView === 'waf-event' && eventId"
      :event-id="eventId"
      @back="backFromEventDetail"
      @close="closeOverlay"
    />
  </div>
</template>

<script setup lang="ts">
const auth = useUiAuth()
const { authed, ready, init, logout, user } = auth

async function onLogout() {
  await logout()
}

const {
  view: hashView,
  eventId,
  eventsParams,
  openWafEventDetail,
  closeOverlay,
  backFromEventDetail,
} = useHashAppView()

function onOpenWafEvent(id: number) {
  openWafEventDetail(id, eventsParams.value)
}

type TabId = 'dashboard' | 'sites' | 'policies' | 'antivirus' | 'qfeed' | 'bots' | 'logging' | 'ai' | 'settings'

const tab = ref<TabId>('dashboard')
const tabs: { id: TabId; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Дашборд', icon: '📊' },
  { id: 'sites', label: 'Сайты', icon: '🌐' },
  { id: 'policies', label: 'Политики', icon: '📋' },
  { id: 'antivirus', label: 'Антивирус', icon: '🦠' },
  { id: 'qfeed', label: 'Q-feed', icon: '📡' },
  { id: 'bots', label: 'Боты', icon: '🤖' },
  { id: 'logging', label: 'Логирование', icon: '📝' },
  { id: 'ai', label: 'ИИ', icon: '✨' },
  { id: 'settings', label: 'Настройки', icon: '⚙️' },
]

onMounted(() => {
  void init()
})
</script>
