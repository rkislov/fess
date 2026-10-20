<template>
  <div class="space-y-5">
    <div
      class="flex flex-wrap gap-2 rounded-2xl border border-white/10 bg-slate-900/40 p-2 shadow-inner shadow-black/20"
      role="tablist"
      aria-label="Разделы журналов"
    >
      <button
        v-for="s in subs"
        :key="s.id"
        type="button"
        role="tab"
        :aria-selected="sub === s.id"
        class="rounded-xl px-3 py-2 text-sm font-medium transition-all duration-200 sm:px-4"
        :class="
          sub === s.id
            ? 'bg-gradient-to-r from-teal-600/90 to-emerald-700 text-white shadow-md shadow-teal-950/30'
            : 'text-slate-400 hover:bg-slate-800/80 hover:text-white'
        "
        @click="sub = s.id"
      >
        <span class="mr-1.5 opacity-80" aria-hidden="true">{{ s.icon }}</span>
        {{ s.label }}
      </button>
    </div>

    <WafRuleLogsPanel v-if="sub === 'rules'" />
    <ProxyAccessLogsPanel v-else-if="sub === 'access'" />
    <MalwareScanLogsPanel v-else-if="sub === 'antivirus'" />
    <PanelLoginLogPanel v-else-if="sub === 'loginlog'" />
  </div>
</template>

<script setup lang="ts">
type LogSubId = 'rules' | 'access' | 'antivirus' | 'loginlog'

const sub = ref<LogSubId>('rules')
const subs: { id: LogSubId; label: string; icon: string }[] = [
  { id: 'rules', label: 'Правила WAF', icon: '⚡' },
  { id: 'access', label: 'Соединения', icon: '📡' },
  { id: 'antivirus', label: 'Антивирус', icon: '🦠' },
  { id: 'loginlog', label: 'Вход (журнал)', icon: '🔐' },
]
</script>
