<template>
  <div
    class="flex flex-wrap items-end gap-3 rounded-xl border border-white/10 bg-slate-900/60 p-3 shadow-inner shadow-black/20"
    role="search"
  >
    <label class="min-w-[12rem] flex-1">
      <span class="mb-1 block text-xs font-medium text-slate-500">Поиск по всем полям</span>
      <input
        :value="q"
        type="search"
        autocomplete="off"
        placeholder="IP, host, path, request_id…"
        class="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-teal-500/60 focus:outline-none focus:ring-1 focus:ring-teal-500/40"
        @input="onQInput"
        @keydown.enter.prevent="emit('apply')"
      />
    </label>
    <label v-if="showHours" class="shrink-0">
      <span class="mb-1 block text-xs font-medium text-slate-500">Период</span>
      <select
        :value="hours"
        class="h-[38px] rounded-lg border border-slate-600 bg-slate-800 px-2 text-sm text-white"
        @change="onHoursChange"
      >
        <option :value="0">Всё время</option>
        <option :value="6">6 ч</option>
        <option :value="24">24 ч</option>
        <option :value="72">3 суток</option>
        <option :value="168">7 суток</option>
        <option :value="720">30 суток</option>
      </select>
    </label>
    <slot name="filters" />
    <div class="flex shrink-0 gap-2 pb-0.5">
      <button
        type="button"
        class="rounded-lg bg-gradient-to-r from-teal-600/90 to-emerald-700 px-4 py-2 text-sm font-medium text-white shadow-md shadow-teal-950/30 hover:from-teal-500 hover:to-emerald-600"
        @click="emit('apply')"
      >
        Найти
      </button>
      <button
        type="button"
        class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-300 hover:bg-slate-700"
        @click="emit('reset')"
      >
        Сброс
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    q?: string
    hours?: number
    showHours?: boolean
  }>(),
  { q: '', hours: 0, showHours: true },
)

const emit = defineEmits<{
  'update:q': [value: string]
  'update:hours': [value: number]
  apply: []
  reset: []
}>()

function onQInput(e: Event) {
  emit('update:q', (e.target as HTMLInputElement).value)
}

function onHoursChange(e: Event) {
  emit('update:hours', Number((e.target as HTMLSelectElement).value))
}
</script>
