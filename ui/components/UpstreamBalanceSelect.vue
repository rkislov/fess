<template>
  <div class="space-y-2">
    <label class="block text-xs text-slate-400">
      Распределение между upstream
      <select v-model="mode" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200" @change="keyName = ''">
        <option value="priority">Первый по приоритету</option>
        <option value="round_robin">По кругу (round robin)</option>
        <option value="ip_hash">Хеш по IP клиента</option>
        <option value="path_hash">Хеш по пути URL</option>
        <option value="header_hash">Хеш по заголовку HTTP</option>
        <option value="cookie_hash">Хеш по cookie</option>
      </select>
    </label>
    <label v-if="namedKey" class="block text-xs text-slate-400">
      {{ mode === 'cookie_hash' ? 'Имя cookie' : 'Имя заголовка' }}
      <input v-model.trim="keyName" :placeholder="mode === 'cookie_hash' ? 'session_id' : 'X-Tenant-ID'" maxlength="128"
        class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200" />
    </label>
    <p v-if="mode !== 'priority'" class="text-xs text-slate-400">
      Распределение работает между включёнными upstream с одинаковым путём и приоритетами.
      <template v-if="namedKey">Если значение отсутствует, используется IP клиента.</template>
      <template v-else-if="mode === 'path_hash'">Параметры запроса не входят в хеш.</template>
    </p>
  </div>
</template>

<script setup lang="ts">
const mode = defineModel<string>('mode', { required: true })
const keyName = defineModel<string>('keyName', { required: true })
const namedKey = computed(() => mode.value === 'cookie_hash' || mode.value === 'header_hash')
</script>
