<template>
  <div
    class="flex flex-col gap-3 border-t border-slate-800/80 pt-4 text-sm text-slate-400 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between"
  >
    <span>{{ rangeText }}</span>
    <div class="flex flex-wrap items-center gap-2">
      <label class="flex items-center gap-2">
        <span class="text-slate-500">На странице</span>
        <select
          :value="pageSize"
          class="rounded-lg border border-slate-600 bg-slate-800 px-2 py-1.5 text-white"
          :disabled="busy"
          @change="onSize($event)"
        >
          <option v-for="n in sizes" :key="n" :value="n">{{ n }}</option>
        </select>
      </label>
      <button
        type="button"
        class="rounded-lg bg-slate-800 px-3 py-1.5 hover:bg-slate-700 disabled:opacity-40"
        :disabled="busy || page <= 1"
        @click="emit('update:page', page - 1)"
      >
        Назад
      </button>
      <span class="min-w-[5rem] text-center font-mono text-slate-300">{{ page }} / {{ totalPages }}</span>
      <button
        type="button"
        class="rounded-lg bg-slate-800 px-3 py-1.5 hover:bg-slate-700 disabled:opacity-40"
        :disabled="busy || page >= totalPages"
        @click="emit('update:page', page + 1)"
      >
        Вперёд
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    total: number
    page: number
    pageSize: number
    busy?: boolean
  }>(),
  { busy: false },
)

const emit = defineEmits<{
  (e: 'update:page', v: number): void
  (e: 'update:pageSize', v: number): void
}>()

const sizes = [25, 50, 100, 200] as const

const totalPages = computed(() => {
  const ps = Math.max(1, props.pageSize)
  return Math.max(1, Math.ceil(props.total / ps))
})

const rangeText = computed(() => {
  const t = props.total
  if (t === 0) return 'Записей нет'
  const from = (props.page - 1) * props.pageSize + 1
  const to = Math.min(props.page * props.pageSize, t)
  return `Записи ${from}–${to} из ${t}`
})

function onSize(ev: Event) {
  const el = ev.target as HTMLSelectElement
  const n = parseInt(el.value, 10)
  if (!Number.isNaN(n)) emit('update:pageSize', n)
}
</script>
