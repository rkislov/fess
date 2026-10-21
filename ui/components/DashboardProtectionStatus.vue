<template>
  <section class="grid gap-4 lg:grid-cols-3">
    <article class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 text-sm space-y-2">
      <h3 class="font-semibold text-white">Антивирус ClamAV</h3>
      <p v-if="errors.av" class="text-amber-300">{{ errors.av }}</p>
      <template v-else-if="av">
        <p :class="av.clamd.reachable ? 'text-emerald-300' : 'text-amber-300'">{{ av.clamd.skipped ? 'Выключен' : av.clamd.reachable ? 'Доступен' : 'Недоступен' }}</p>
        <p class="text-slate-300">Движок: {{ av.clamd.engine_version || '—' }} · загруженная ревизия: {{ av.clamd.signature_revision || '—' }}</p>
        <p v-if="av.clamd.probe_error" class="text-amber-300 break-words">{{ av.clamd.probe_error }}</p>
        <p class="text-xs text-slate-500">Базы на диске (могут отличаться от загруженной ревизии):</p>
        <div v-for="db in av.databases" :key="db.file" class="text-xs text-slate-300">
          {{ db.file }}: <span v-if="db.error" class="text-amber-300">{{ db.error }}</span>
          <span v-else>v{{ db.version }} · {{ db.signatures?.toLocaleString('ru-RU') }} сигнатур · {{ date(db.built_at) }}</span>
        </div>
      </template>
    </article>
    <article class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 text-sm space-y-2">
      <h3 class="font-semibold text-white">Блок-лист IOC / FESS Feed</h3>
      <p v-if="errors.feed" class="text-amber-300">{{ errors.feed }}</p>
      <template v-else-if="feed">
        <p class="text-slate-300">{{ !feed.enabled ? 'Выключен' : feed.block ? 'Блокировка включена' : 'Только наблюдение' }}</p>
        <p class="text-slate-300">Индикаторов: {{ feed.indicator_count }} · хешей файлов: {{ feed.file_hash_count }}</p>
        <p v-if="feed.enabled && !(feed.provider === 'fess_feed' ? feed.fess_feed_ready : feed.threatfox_ready)" class="text-amber-300">Проверьте подключение поставщика в настройках IOC.</p>
        <p class="text-xs text-slate-400">Обновление: {{ date(feed.last_success_at) }}</p>
        <p v-if="feed.last_error" class="text-amber-300 break-words">{{ feed.last_error }}</p>
      </template>
    </article>
    <article class="rounded-2xl border border-white/10 bg-slate-900/50 p-5 text-sm space-y-2">
      <h3 class="font-semibold text-white">Блок-листы ASN / CIDR</h3>
      <p v-if="errors.bots" class="text-amber-300">{{ errors.bots }}</p>
      <template v-else-if="bots">
        <p class="text-slate-300">{{ bots.enabled ? 'Защита включена' : 'Защита выключена' }}</p>
        <p class="text-slate-300">ASN: {{ bots.asn_rows }} · CIDR: {{ bots.cidr_rows }}</p>
        <p class="text-xs text-slate-400">Обновление: {{ date(bots.last_success_at) }}</p>
        <p v-if="bots.last_error" class="text-amber-300 break-words">{{ bots.last_error }}</p>
      </template>
    </article>
  </section>
</template>
<script setup lang="ts">
const props = defineProps<{ refreshKey?: string | number | null }>()
const { apiFetch, apiUrl } = useApi()
const av = ref<any>(null), feed = ref<any>(null), bots = ref<any>(null)
const errors = reactive({ av: '', feed: '', bots: '' })
let generation = 0
function date(value?: string) { return value ? new Date(value).toLocaleString('ru-RU') : 'ещё не обновлялось' }
async function load() {
  const current = ++generation
  const results = await Promise.allSettled([
    apiFetch(apiUrl('/settings/malware/status')),
    apiFetch(apiUrl('/settings/threat-feed/status')),
    apiFetch(apiUrl('/settings/bot-protection/status')),
  ])
  if (generation !== current) return
  const values = [av, feed, bots]
  const names = ['av', 'feed', 'bots'] as const
  results.forEach((result, i) => {
    errors[names[i]] = result.status === 'rejected' ? 'Статус недоступен. Обновите дашборд.' : ''
    values[i].value = result.status === 'fulfilled' ? result.value : null
  })
}
onMounted(load)
watch(() => props.refreshKey, load)
onBeforeUnmount(() => { ++generation })
</script>
