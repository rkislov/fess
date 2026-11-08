<template>
  <section id="waf-feed-packs" class="scroll-mt-40 space-y-5 rounded-2xl sm:scroll-mt-28 border border-teal-800 bg-slate-900/70 p-6">
    <h2 class="text-lg font-semibold text-white">Наборы правил для приложений · Feed</h2>
    <p class="text-sm text-slate-300">Из заготовки можно создать политику WAF для сайта. Новая политика выключена и использует режим наблюдения (log). Включите и опубликуйте её, когда правила готовы.</p>
    <p v-if="message" role="status" class="text-sm text-teal-200">{{ message }}</p>
    <p v-if="error" role="alert" class="text-sm text-rose-300">{{ error }}</p>
    <p v-if="catalogError" role="alert" class="text-sm text-rose-300">Каталог недоступен. {{ catalogError }}</p>
    <p v-else-if="loading" role="status" class="text-sm text-slate-400">Загружаем заготовки…</p>
    <p v-else-if="!profiles.length" class="text-sm text-slate-400">В каталоге пока нет заготовок.</p>
    <div class="flex flex-wrap items-center gap-3">
      <button type="button" class="rounded bg-teal-700 px-3 py-2 disabled:opacity-40" :disabled="loading || busy" @click="loadCatalog">Обновить каталог</button>
    </div>
    <p class="text-xs text-slate-400">Профили защищают служебные пути приложений, установленных в корне домена.</p>
    <div class="grid gap-3 md:grid-cols-2">
      <article v-for="p in profiles" :key="profileChoice(p)" class="rounded border border-slate-700 p-3">
        <p>{{ p.title }} · {{ p.version }} · Правил: {{ p.rule_count }}</p>
        <p class="mt-1 text-xs text-slate-400">{{ p.policy_id ? 'Есть в политиках WAF' : 'Доступна заготовка' }}</p>
        <button type="button" class="mt-2 rounded bg-slate-700 px-3 py-1 text-sm disabled:opacity-40" :disabled="busy || loading" @click="openProfile(p)">{{ p.policy_id ? 'Открыть политику' : 'Добавить в политики' }}</button>
      </article>
    </div>
    <div class="space-y-3 border-t border-slate-700 pt-4">
      <h3 class="font-medium">Адаптация по трафику</h3>
      <p class="text-sm text-slate-400">Выберите опубликованную политику log. Сводка за 24 часа показывает первое сработавшее правило каждого запроса. Частота не доказывает ложное срабатывание. Проверьте запросы в журнале, прежде чем добавлять исключение.</p>
      <select v-model="policyId" aria-label="Политика для адаптации" class="max-w-full rounded bg-slate-950 px-3 py-2" @change="hits = []">
        <option value="">Выберите политику log</option>
        <option v-for="p in logPolicies" :key="p.id" :value="p.id">{{ p.name }}</option>
      </select>
      <button class="ml-2 rounded border border-teal-700 px-3 py-2 disabled:opacity-40" :disabled="busy || !policyId" @click="loadHits">Обновить срабатывания</button>
      <p class="text-xs text-slate-400">Исключение относится только к одному правилу и точной комбинации Host + Path + Method, для всех query/body на этом пути. Сохраняется в черновик; применится после публикации политики.</p>
      <p v-if="hitsLoaded && !hits.length" class="text-sm text-slate-400">Срабатываний за выбранный период нет.</p>
      <article v-for="(h, i) in hits" :key="i" class="space-y-2 rounded border border-slate-700 p-3 text-sm">
        <p class="break-all font-mono">{{ h.method }} {{ h.host }}{{ h.path }} · {{ h.count }} срабатываний</p>
        <p class="text-xs text-slate-400">Правило {{ h.rule_id }}</p>
        <label class="block"><input v-model="h.confirmed" type="checkbox" /> Проверил: запрос легитимный, исключение допустимо</label>
        <button class="rounded bg-slate-700 px-3 py-2 disabled:opacity-40" :disabled="busy || !h.confirmed" @click="exception(h)">Сохранить исключение в черновик</button>
      </article>
    </div>
  </section>
</template>
<script setup lang="ts">
import type { WafProfile } from '~/composables/useWafProfiles'
const props = defineProps<{policies: {id:string;name:string;mode:string}[]}>()
const emit = defineEmits<{changed: [policyId?: string]}>()
const {apiUrl,apiFetch}=useApi()
const { profiles, loading, catalogError, loadCatalog, policyFor } = useWafProfiles()
const busy=ref(false),error=ref(''),message=ref(''),hits=ref<any[]>([]),policyId=ref(''),hitsLoaded=ref(false)
const logPolicies=computed(()=>props.policies.filter(p=>p.mode==='log'))
async function run(fn:()=>Promise<void>){busy.value=true;error.value='';message.value='';try{await fn()}catch(e:any){error.value=e?.data?.error || e?.message || 'Ошибка запроса'}finally{busy.value=false}}
async function openProfile(profile: WafProfile) {
  await run(async () => { emit('changed', await policyFor(profile)) })
}
async function loadHits(){await run(async()=>{const r=await apiFetch<any>(apiUrl('/waf-feed/adaptation/hits')+'?policy_id='+encodeURIComponent(policyId.value));hits.value=r.items.map((h:any)=>({...h,confirmed:false}));hitsLoaded.value=true})}
async function exception(h:any){await run(async()=>{await apiFetch(apiUrl('/waf-feed/adaptation/exception'),{method:'POST',body:{rule_id:h.rule_id,confirmed:h.confirmed,exception:{host:h.host,path:h.path,method:h.method}}});message.value='Исключение сохранено в черновик. Проверьте JSON правила и опубликуйте политику.';h.confirmed=false;emit('changed')})}
onMounted(loadCatalog)
</script>
