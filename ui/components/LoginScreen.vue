<template>
  <div
    class="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-gradient-to-br from-slate-950 via-indigo-950/40 to-slate-950 px-4 py-12"
  >
    <div
      class="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(99,102,241,0.22),transparent)]"
    />
    <div
      class="pointer-events-none absolute -right-32 top-1/4 h-72 w-72 rounded-full bg-teal-500/10 blur-3xl"
    />
    <div
      class="pointer-events-none absolute -left-32 bottom-1/4 h-72 w-72 rounded-full bg-indigo-500/10 blur-3xl"
    />

    <div class="relative w-full max-w-md">
      <div class="mb-8 text-center">
        <div
          class="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-teal-400 to-indigo-500 text-2xl shadow-lg shadow-indigo-900/40"
          aria-hidden="true"
        >
          🛡️
        </div>
        <h1 class="text-2xl font-semibold tracking-tight text-white">FESS</h1>
        <p class="mt-2 text-sm text-slate-400">Frontend Security Server — панель управления WAF, антивирусом и сайтами</p>
      </div>

      <form
        class="rounded-2xl border border-white/10 bg-slate-900/70 p-8 shadow-2xl shadow-black/40 backdrop-blur-md"
        @submit.prevent="submit"
      >
        <p v-if="err" class="mb-4 rounded-lg border border-rose-500/30 bg-rose-950/50 px-3 py-2 text-sm text-rose-200">
          {{ err }}
        </p>

        <label class="block">
          <span class="text-sm font-medium text-slate-300">Логин</span>
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            class="mt-1.5 w-full rounded-xl border border-slate-600/80 bg-slate-950/80 px-4 py-3 text-slate-100 outline-none ring-2 ring-transparent transition placeholder:text-slate-600 focus:border-teal-500/50 focus:ring-teal-500/25"
            placeholder="Введите логин"
          />
        </label>

        <label class="mt-5 block">
          <span class="text-sm font-medium text-slate-300">Пароль</span>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="mt-1.5 w-full rounded-xl border border-slate-600/80 bg-slate-950/80 px-4 py-3 text-slate-100 outline-none ring-2 ring-transparent transition placeholder:text-slate-600 focus:border-teal-500/50 focus:ring-teal-500/25"
            placeholder="Введите пароль"
          />
        </label>

        <button
          type="submit"
          class="mt-8 w-full rounded-xl bg-gradient-to-r from-teal-500 to-emerald-600 px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 transition hover:from-teal-400 hover:to-emerald-500 focus:outline-none focus:ring-2 focus:ring-teal-400/50 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="busy"
        >
          {{ busy ? 'Вход…' : 'Войти' }}
        </button>

        <p class="mt-6 text-center text-xs leading-relaxed text-slate-500">
          По умолчанию после первого запуска:
          <code class="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">admin</code>
          /
          <code class="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">fence</code>
          <br />
          <span class="text-slate-600">Поддерживаются локальная и доменная (LDAP) авторизация — настройка в разделе «Настройки».</span>
        </p>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
const auth = useUiAuth()
const username = ref('')
const password = ref('')
const err = ref('')
const busy = ref(false)

async function submit() {
  err.value = ''
  busy.value = true
  try {
    const r = await auth.login(username.value, password.value)
    appendPanelLoginEntry(username.value, r.ok)
    if (!r.ok) err.value = r.message
  } finally {
    busy.value = false
  }
}
</script>
