<template>
  <div class="space-y-1">
    <label class="block text-xs text-slate-500">
      Политика WAF
      <select v-model="choice" :disabled="disabled" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
        <option value="">Все включённые политики</option>
        <optgroup v-if="policies.length" label="Политики WAF">
          <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
        </optgroup>
        <optgroup v-if="profiles.length" label="Заготовки политик">
          <option v-for="p in profiles" :key="profileChoice(p)" :value="profileChoice(p)">
            {{ p.title }} · {{ p.version }}{{ p.policy_id ? ' · есть в политиках' : '' }}
          </option>
        </optgroup>
      </select>
    </label>
    <p v-if="loading" class="text-xs text-slate-400">Загружаем заготовки…</p>
    <p v-else-if="catalogError" class="text-xs text-amber-300">Каталог заготовок недоступен. {{ catalogError }}
      <button type="button" class="underline" :disabled="disabled" @click="loadCatalog">Повторить</button>
    </p>
    <p v-else-if="!profiles.length" class="text-xs text-slate-400">В каталоге пока нет заготовок.</p>
    <p v-if="selected && !selected.policy_id" class="text-xs text-amber-300">
      При сохранении сайт перейдёт на новую политику в режиме наблюдения (log).
      Запросы будут проходить без проверки правилами WAF, пока вы не включите и не опубликуете политику в «Политики WAF».
    </p>
    <p v-else-if="selected" class="text-xs text-slate-400">
      При сохранении сайт будет использовать существующую политику «{{ policies.find(p => p.id === selected?.policy_id)?.name || selected.title }}».
    </p>
  </div>
</template>

<script setup lang="ts">
defineProps<{ policies: { id: string; name: string }[]; disabled: boolean }>()
const choice = defineModel<string>({ required: true })
const emit = defineEmits<{ added: [] }>()
const { profiles, loading, catalogError, loadCatalog, policyFor } = useWafProfiles()
const selected = computed(() => profiles.value.find(p => profileChoice(p) === choice.value))

async function resolvePolicy() {
  if (!choice.value.startsWith('feed:')) return choice.value
  const profile = selected.value
  if (!profile) throw new Error('Заготовка недоступна. Выберите политику снова.')
  const wasAdded = !!profile.policy_id
  const id = await policyFor(profile)
  if (!wasAdded) emit('added')
  return id
}

defineExpose({ resolvePolicy })
onMounted(loadCatalog)
</script>
