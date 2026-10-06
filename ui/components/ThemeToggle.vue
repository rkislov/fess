<template>
  <div
    class="inline-flex rounded-lg border p-0.5"
    :class="
      compact
        ? isLight
          ? 'border-stone-900/15 bg-white/70'
          : 'border-white/15 bg-black/30'
        : isLight
          ? 'border-stone-900/10 bg-white/80'
          : 'border-white/10 bg-slate-950/40'
    "
    role="group"
    aria-label="Тема оформления"
  >
    <button
      v-for="opt in options"
      :key="opt.id"
      type="button"
      class="rounded-md px-2 py-1 text-[0.7rem] font-semibold uppercase tracking-wider transition sm:px-2.5"
      :class="
        preference === opt.id
          ? 'bg-[#e11d2e] text-white'
          : 'text-inherit opacity-80 hover:opacity-100'
      "
      :title="opt.title"
      @click="setPreference(opt.id)"
    >
      {{ compact ? opt.short : opt.label }}
    </button>
  </div>
</template>

<script setup lang="ts">
import type { UiThemePreference } from '~/composables/useUiTheme'

defineProps<{ compact?: boolean }>()

const { preference, resolved, setPreference } = useUiTheme()
const isLight = computed(() => resolved.value === 'light')

const options: { id: UiThemePreference; short: string; label: string; title: string }[] = [
  { id: 'dark', short: 'Тёмн.', label: 'Тёмная', title: 'Тёмная тема' },
  { id: 'light', short: 'Светл.', label: 'Светлая', title: 'Светлая тема' },
  { id: 'system', short: 'Авто', label: 'Как в системе', title: 'Как в операционной системе' },
]
</script>
