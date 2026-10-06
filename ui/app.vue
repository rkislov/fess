<template>
  <div
    v-if="!ready"
    class="relative flex min-h-screen items-center justify-center overflow-hidden"
    :class="isLight ? 'bg-[#f4efe6] text-stone-700' : 'bg-[#080809] text-[#d8d2c6]'"
  >
    <div
      class="pointer-events-none absolute inset-0 bg-cover bg-center bg-no-repeat opacity-50"
      style="background-image: url('/brand/splash.jpg')"
    />
    <div class="relative flex flex-col items-center gap-3">
      <div
        class="h-10 w-10 animate-spin rounded-full border-2 border-t-[#e11d2e]"
        :class="isLight ? 'border-stone-400/40' : 'border-white/20'"
        aria-hidden="true"
      />
      <p class="text-sm">Загрузка…</p>
    </div>
  </div>

  <LoginScreen v-else-if="!canUseApp()" />

  <div
    v-else
    class="relative min-h-screen antialiased"
    :class="isLight ? 'text-stone-800' : 'text-[#f4f1ea]'"
  >
    <div
      class="pointer-events-none fixed inset-0 -z-10 bg-cover bg-center bg-no-repeat"
      :class="isLight ? 'bg-[#f4efe6]' : 'bg-[#080809]'"
      style="background-image: url('/brand/splash.jpg')"
    />
    <div class="pointer-events-none fixed inset-0 -z-10 fess-mural-veil" />

    <header
      class="sticky top-0 z-20 border-b px-4 py-3 backdrop-blur-md sm:px-6 sm:py-4"
      :class="isLight ? 'border-stone-900/10 bg-white/70' : 'border-white/10 bg-black/50'"
    >
      <div class="mx-auto flex max-w-6xl flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <img
            src="/brand/splash-mark.jpg"
            alt=""
            width="44"
            height="44"
            class="h-11 w-11 shrink-0 rounded-xl object-cover shadow-md ring-1 ring-black/10"
          />
          <div>
            <h1
              class="text-lg font-semibold tracking-tight sm:text-xl"
              :class="isLight ? 'text-stone-900' : 'text-white'"
            >
              FESS — Frontend Security Server
            </h1>
            <p class="mt-0.5 text-[0.72rem] font-bold uppercase tracking-[0.28em] text-[#e11d2e]">
              Дашборд · сайты · УЦ
            </p>
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-2 self-start sm:self-center">
          <ThemeToggle compact />
          <button
            type="button"
            class="fess-logout-btn rounded border px-3 py-2 text-xs font-semibold uppercase tracking-wider transition hover:border-[#e11d2e]/60 hover:bg-[#e11d2e] hover:text-white"
            @click="onLogout"
          >
            Выйти
          </button>
        </div>
      </div>
    </header>

    <nav
      class="border-b px-4 py-3 sm:px-6"
      :class="isLight ? 'border-stone-900/10 bg-white/45' : 'border-white/10 bg-black/35'"
    >
      <div class="mx-auto max-w-6xl overflow-x-auto pb-1">
        <div class="flex min-w-max flex-wrap gap-2">
          <button
            v-for="t in tabs"
            :key="t.id"
            type="button"
            class="rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200 sm:px-4"
            :class="
              tab === t.id
                ? 'bg-[#e11d2e] text-white shadow-md shadow-black/20'
                : isLight
                  ? 'bg-white/80 text-stone-700 hover:bg-white hover:text-stone-900'
                  : 'bg-black/45 text-[#ddd7cc] hover:bg-black/70 hover:text-white'
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
      <CertificatesPanel v-else-if="tab === 'ca'" />
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
const { ready, logout, canUseApp } = auth
const { resolved: uiTheme } = useUiTheme()
const isLight = computed(() => uiTheme.value === 'light')

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

type TabId = 'dashboard' | 'sites' | 'ca' | 'settings'

const tab = ref<TabId>('dashboard')
const tabs: { id: TabId; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Дашборд', icon: '📊' },
  { id: 'sites', label: 'Сайты', icon: '🌐' },
  { id: 'ca', label: 'УЦ', icon: '🔐' },
  { id: 'settings', label: 'Настройки', icon: '⚙️' },
]
</script>
