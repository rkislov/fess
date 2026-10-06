<template>
  <div
    class="relative flex min-h-screen flex-col overflow-hidden bg-cover bg-center bg-no-repeat"
    :class="isLight ? 'bg-[#f4efe6] text-stone-800' : 'bg-[#080809] text-[#f4f1ea]'"
    style="background-image: url('/brand/splash.jpg')"
  >
    <div class="flex min-h-screen flex-col justify-end fess-login-veil">
      <main class="mx-auto w-full max-w-xl px-6 pb-8 pt-16 sm:px-8">
        <p class="text-[0.72rem] font-bold uppercase tracking-[0.38em] text-[#e11d2e]">FESS</p>
        <h1
          class="mt-2 text-[clamp(2.4rem,8vw,4.4rem)] font-extrabold uppercase leading-[0.95] tracking-tight [text-shadow:0_2px_0_rgb(0_0_0_/_0.35)]"
          :class="isLight ? 'text-stone-900' : 'text-white'"
        >
          Войти
        </h1>
        <p class="mt-3 max-w-md text-[1.05rem]" :class="isLight ? 'text-stone-700' : 'text-[#ddd7cc]'">
          Frontend Security Server — панель управления WAF, антивирусом и сайтами.
        </p>

        <form class="mt-8 max-w-md space-y-4" @submit.prevent="submit">
          <p
            v-if="err"
            class="rounded border border-rose-500/40 bg-rose-950/70 px-3 py-2 text-sm text-rose-100"
          >
            {{ err }}
          </p>

          <label class="block">
            <span
              class="text-xs font-semibold uppercase tracking-wider"
              :class="isLight ? 'text-stone-500' : 'text-[#9a958c]'"
            >Логин</span>
            <input
              v-model="username"
              type="text"
              autocomplete="username"
              class="mt-1.5 w-full border px-4 py-3 outline-none focus:border-[#e11d2e]"
              :class="
                isLight
                  ? 'border-stone-900/15 bg-white/80 text-stone-900 placeholder:text-stone-400'
                  : 'border-white/15 bg-black/55 text-[#f4f1ea] placeholder:text-[#6e6a63]'
              "
              placeholder="Введите логин"
            />
          </label>

          <label class="block">
            <span
              class="text-xs font-semibold uppercase tracking-wider"
              :class="isLight ? 'text-stone-500' : 'text-[#9a958c]'"
            >Пароль</span>
            <input
              v-model="password"
              type="password"
              autocomplete="current-password"
              class="mt-1.5 w-full border px-4 py-3 outline-none focus:border-[#e11d2e]"
              :class="
                isLight
                  ? 'border-stone-900/15 bg-white/80 text-stone-900 placeholder:text-stone-400'
                  : 'border-white/15 bg-black/55 text-[#f4f1ea] placeholder:text-[#6e6a63]'
              "
              placeholder="Введите пароль"
            />
          </label>

          <button
            type="submit"
            class="mt-2 inline-flex min-w-[10rem] items-center justify-center bg-[#e11d2e] px-5 py-3 text-sm font-bold uppercase tracking-wider text-white hover:bg-[#c41826] disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="busy"
          >
            {{ busy ? 'Вход…' : 'Войти' }}
          </button>
        </form>
      </main>

      <footer
        class="flex flex-col gap-3 border-t px-6 py-3 text-xs sm:flex-row sm:items-center sm:justify-between sm:px-8"
        :class="isLight ? 'border-stone-900/10 text-stone-500' : 'border-white/10 text-[#8c877e]'"
      >
        <p>
          Стрит-арт для FESS · автор
          <strong class="font-semibold" :class="isLight ? 'text-stone-800' : 'text-[#d8d2c6]'">Роман Сергеевич Кислов</strong>
          (Roman Sergeyevich Kislov) · Apache-2.0
        </p>
        <ThemeToggle compact />
      </footer>
    </div>
  </div>
</template>

<script setup lang="ts">
const auth = useUiAuth()
const { resolved } = useUiTheme()
const isLight = computed(() => resolved.value === 'light')
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
