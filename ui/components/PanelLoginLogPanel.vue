<template>
  <div class="space-y-6">
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Журнал входов в панель</h2>
      <p class="mt-1 text-sm text-slate-400">
        Записи хранятся только в этом браузере (sessionStorage). Не путать с аудитом API на сервере.
      </p>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
          @click="refresh"
        >
          Обновить
        </button>
        <button
          type="button"
          class="rounded-lg border border-rose-500/40 px-4 py-2 text-sm text-rose-200 hover:bg-rose-950/40"
          @click="clear"
        >
          Очистить журнал
        </button>
      </div>
      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="py-2 pr-4">Время</th>
              <th class="py-2 pr-4">Логин</th>
              <th class="py-2">Результат</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!rows.length">
              <td colspan="3" class="py-8 text-center text-slate-500">Пока нет записей</td>
            </tr>
            <tr v-for="(e, i) in rows" :key="i" class="border-b border-slate-800/80">
              <td class="py-2 pr-4 font-mono text-xs text-slate-400">{{ formatT(e.t) }}</td>
              <td class="py-2 pr-4">{{ e.user }}</td>
              <td class="py-2">
                <span
                  class="rounded-full px-2 py-0.5 text-xs font-medium"
                  :class="e.ok ? 'bg-emerald-950/60 text-emerald-300' : 'bg-rose-950/60 text-rose-300'"
                >
                  {{ e.ok ? 'Успех' : 'Отказ' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
const rows = ref<{ t: string; user: string; ok: boolean }[]>([])

function refresh() {
  rows.value = readPanelLoginLog()
}

function clear() {
  if (!confirm('Удалить все записи журнала входа в этом браузере?')) return
  clearPanelLoginLog()
  refresh()
}

function formatT(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}

onMounted(() => refresh())
</script>
