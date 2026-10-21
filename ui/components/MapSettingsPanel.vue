<template>
  <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 space-y-4">
    <h3 class="text-sm font-semibold text-white">Карта на дашборде</h3>
    <p class="text-sm text-slate-400">Leaflet — библиотека отображения карты. API key нужен выбранному поставщику подложки.</p>
    <label class="block text-sm text-slate-300">Поставщик
      <select v-model="settings.provider" class="mt-1 block rounded border border-slate-600 bg-slate-900 p-2">
        <option value="carto">CARTO / Leaflet</option><option value="yandex">Яндекс Карты</option>
      </select>
    </label>
    <label class="block text-sm text-slate-300">API key
      <input v-model="settings.api_key" autocomplete="off" spellcheck="false" maxlength="1024" class="mt-1 block w-full rounded border border-slate-600 bg-slate-900 p-2 font-mono" placeholder="Ключ выбранного поставщика" />
    </label>
    <p class="text-xs text-slate-400">Ключ используется браузером и доступен пользователям панели. Ограничьте его доменом вашей установки в кабинете поставщика. При смене поставщика введите соответствующий ключ.</p>
    <a :href="settings.provider === 'yandex' ? 'https://developer.tech.yandex.ru/keys/' : 'https://www.carto.com/basemaps/apikey/index.html'" target="_blank" rel="noopener noreferrer" class="block text-sm text-teal-400">Получить ключ {{ settings.provider === 'yandex' ? 'JavaScript API Яндекс Карт' : 'CARTO Basemaps' }} ↗</a>
    <button :disabled="busy || !loaded" class="rounded bg-teal-600 px-4 py-2 text-sm text-white disabled:opacity-50" @click="save">Сохранить</button>
    <p role="status" class="text-sm text-slate-300">{{ message }}</p>
  </section>
</template>
<script setup lang="ts">
const { apiFetch, apiUrl } = useApi()
const settings = ref({ provider: 'carto', api_key: '' })
const busy = ref(false)
const loaded = ref(false)
const message = ref('')
onMounted(async () => {
  try { settings.value = await apiFetch<typeof settings.value>(apiUrl('/settings/map')); loaded.value = true }
  catch { message.value = 'Не удалось загрузить настройки карты.' }
})
async function save() {
  busy.value = true
  try {
    settings.value = await apiFetch<typeof settings.value>(apiUrl('/settings/map'), { method: 'PUT', body: settings.value })
    message.value = 'Сохранено. Карта применит настройки при обновлении дашборда.'
  } catch { message.value = 'Не удалось сохранить настройки карты.' }
  finally { busy.value = false }
}
</script>
