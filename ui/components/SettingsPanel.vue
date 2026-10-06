<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <div class="flex flex-wrap gap-2">
      <button
        v-for="s in visibleSections"
        :key="s.id"
        type="button"
        class="rounded-lg px-3 py-2 text-sm font-medium transition"
        :class="sub === s.id ? 'bg-teal-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'"
        @click="sub = s.id"
      >
        {{ s.icon }} {{ s.label }}
      </button>
      <button
        v-if="sub === 'users' || sub === 'auth' || sub === 'siem' || sub === 'ai'"
        type="button"
        class="ml-auto rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
        :disabled="busy"
        @click="loadAdmin"
      >
        Обновить
      </button>
    </div>

    <section v-if="sub === 'appearance'" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Оформление</h3>
      <p class="mt-0.5 text-xs text-slate-500">
        Стрит-арт остаётся фоном. Светлая тема осветляет вуаль и карточки. Выбор хранится в этом браузере.
      </p>
      <div class="mt-4">
        <ThemeToggle />
      </div>
      <p class="mt-3 text-xs text-slate-500">
        Сейчас:
        <span class="font-medium text-slate-300">{{ appearanceHint }}</span>
      </p>
    </section>

    <!-- Admin: users -->
    <section v-else-if="sub === 'users' && isAdmin" class="space-y-6">
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <h3 class="text-sm font-semibold text-white">Пользователи</h3>
        <p class="mt-0.5 text-xs text-slate-500">Локальные учётные записи и записи после входа через LDAP</p>
        <ul class="mt-4 space-y-2 text-sm">
          <li v-if="!users.length" class="text-slate-500">Нет пользователей</li>
          <li
            v-for="u in users"
            :key="u.id"
            class="flex flex-col gap-2 rounded-lg bg-slate-800/60 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between"
          >
            <span class="min-w-0 flex-1">
              <span class="font-medium text-slate-200">{{ u.display_name || u.username }}</span>
              <span class="ml-2 font-mono text-[10px] text-slate-500">{{ u.username }}</span>
              <span class="ml-2 rounded bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-400">{{ u.auth_provider }}</span>
            </span>
            <select
              v-model="u.role"
              class="rounded border border-slate-600 bg-slate-900 px-2 py-1 text-xs"
              @change="saveUser(u)"
            >
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="viewer">viewer</option>
            </select>
            <label class="flex items-center gap-1.5 text-slate-400">
              <input v-model="u.active" type="checkbox" class="rounded" @change="saveUser(u)" />
              активен
            </label>
          </li>
        </ul>
      </div>

      <form class="rounded-2xl border border-white/10 bg-slate-900/50 p-6" @submit.prevent="createUser">
        <h3 class="text-sm font-semibold text-white">Новый локальный пользователь</h3>
        <div class="mt-4 grid gap-3 sm:grid-cols-2">
          <label class="block text-xs text-slate-400">
            Логин
            <input v-model="newUser.username" required class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Пароль (мин. 6)
            <input v-model="newUser.password" type="password" required minlength="6" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Имя
            <input v-model="newUser.display_name" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Email
            <input v-model="newUser.email" type="email" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white" />
          </label>
          <label class="block text-xs text-slate-400 sm:col-span-2">
            Роль
            <select v-model="newUser.role" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white">
              <option value="viewer">viewer — только чтение</option>
              <option value="operator">operator — изменение политик и сайтов</option>
              <option value="admin">admin — полный доступ</option>
            </select>
          </label>
        </div>
        <button type="submit" class="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500" :disabled="busy">
          Создать
        </button>
      </form>
    </section>

    <!-- Admin: auth -->
    <section v-else-if="sub === 'auth' && isAdmin" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Авторизация</h3>
      <p class="mt-0.5 text-xs text-slate-500">Локальная и доменная (LDAP / Active Directory)</p>
      <div class="mt-4 space-y-4 text-sm">
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="authCfg.local_auth_enabled" type="checkbox" class="rounded" />
          Локальная авторизация (пользователи из БД)
        </label>
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="authCfg.ldap_enabled" type="checkbox" class="rounded" />
          Доменная авторизация (LDAP)
        </label>
        <label class="block text-xs text-slate-400">
          LDAP URL
          <input v-model="authCfg.ldap_url" placeholder="ldap://dc.example.com:389" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-white" />
        </label>
        <label class="block text-xs text-slate-400">
          Bind DN (сервисная учётка)
          <input v-model="authCfg.ldap_bind_dn" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-white" />
        </label>
        <label class="block text-xs text-slate-400">
          Bind password (оставьте пустым, чтобы не менять)
          <input v-model="ldapBindPassword" type="password" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white" />
        </label>
        <label class="block text-xs text-slate-400">
          Base DN
          <input v-model="authCfg.ldap_base_dn" placeholder="DC=example,DC=com" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-white" />
        </label>
        <label class="block text-xs text-slate-400">
          Фильтр пользователя (%s = логин)
          <input v-model="authCfg.ldap_user_filter" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-white" />
        </label>
        <label class="block text-xs text-slate-400">
          Атрибут логина
          <input v-model="authCfg.ldap_user_attr" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 font-mono text-sm text-white" />
        </label>
      </div>
      <button type="button" class="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500" :disabled="busy" @click="saveAuth">
        Сохранить
      </button>
    </section>

    <div v-else-if="sub === 'ai'" class="space-y-6">
      <AiSettingsPanel v-if="isAdmin" />
      <AiAssistantPanel />
    </div>

    <!-- Admin: SIEM -->
    <section v-else-if="sub === 'siem' && isAdmin" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Экспорт в SIEM</h3>
      <p class="mt-0.5 text-xs text-slate-500">Отправка событий на syslog-сервер в формате CEF или RFC5424</p>
      <div class="mt-4 space-y-4 text-sm">
        <label class="flex items-center gap-2 text-slate-300">
          <input v-model="siem.enabled" type="checkbox" class="rounded" />
          Включить экспорт
        </label>
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block text-xs text-slate-400">
            Формат
            <select v-model="siem.format" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white">
              <option value="cef">CEF (только тело)</option>
              <option value="syslog">Syslog + CEF</option>
            </select>
          </label>
          <label class="block text-xs text-slate-400">
            Протокол
            <select v-model="siem.protocol" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white">
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </select>
          </label>
          <label class="block text-xs text-slate-400">
            Хост SIEM / syslog
            <input v-model="siem.host" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Порт
            <input v-model.number="siem.port" type="number" min="1" max="65535" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Интервал опроса (сек)
            <input v-model.number="siem.poll_interval_sec" type="number" min="5" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
        </div>
        <p class="text-xs font-medium text-slate-400">Потоки событий</p>
        <div class="flex flex-wrap gap-4">
          <label class="flex items-center gap-2 text-slate-300">
            <input v-model="siem.export_waf_logs" type="checkbox" class="rounded" />
            WAF (waf_logs)
          </label>
          <label class="flex items-center gap-2 text-slate-300">
            <input v-model="siem.export_proxy_logs" type="checkbox" class="rounded" />
            Соединения (proxy_access_logs)
          </label>
          <label class="flex items-center gap-2 text-slate-300">
            <input v-model="siem.export_audit_logs" type="checkbox" class="rounded" />
            Аудит (audit_logs)
          </label>
        </div>
        <div class="grid gap-3 sm:grid-cols-3">
          <label class="block text-xs text-slate-400">
            Device Vendor
            <input v-model="siem.device_vendor" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Device Product
            <input v-model="siem.device_product" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
          <label class="block text-xs text-slate-400">
            Device Version
            <input v-model="siem.device_version" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-white" />
          </label>
        </div>
      </div>
      <button type="button" class="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500" :disabled="busy" @click="saveSiem">
        Сохранить
      </button>
    </section>

    <!-- Security tools (all authenticated users) -->
    <PoliciesPanel v-else-if="sub === 'policies'" />
    <MalwarePanel v-else-if="sub === 'antivirus'" />
    <ThreatFeedPanel v-else-if="sub === 'qfeed'" />
    <BotProtectionPanel v-else-if="sub === 'bots'" />
    <RateLimitPanel v-else-if="sub === 'ratelimit'" />
    <ExceptionsPanel v-else-if="sub === 'exceptions'" />
  </div>
</template>

<script setup lang="ts">
import type { AuthUser } from '~/composables/useUiAuth'

const { apiUrl, apiFetch } = useApi()
const auth = useUiAuth()
const isAdmin = computed(() => auth.isAdmin())
const { preference: themePref, resolved: themeResolved } = useUiTheme()

type SubId =
  | 'appearance'
  | 'users'
  | 'auth'
  | 'siem'
  | 'ai'
  | 'policies'
  | 'antivirus'
  | 'qfeed'
  | 'bots'
  | 'ratelimit'
  | 'exceptions'

const appearanceSection = [{ id: 'appearance' as const, label: 'Оформление', icon: '🎨' }]

const adminSections = [
  { id: 'users' as const, label: 'Пользователи', icon: '👤' },
  { id: 'auth' as const, label: 'Авторизация', icon: '🔐' },
  { id: 'siem' as const, label: 'SIEM', icon: '📤' },
  { id: 'ai' as const, label: 'ИИ', icon: '✨' },
]

const securitySections = [
  { id: 'policies' as const, label: 'Политики WAF', icon: '📋' },
  { id: 'antivirus' as const, label: 'Антивирус', icon: '🦠' },
  { id: 'qfeed' as const, label: 'IOC / ThreatFox', icon: '📡' },
  { id: 'bots' as const, label: 'Боты', icon: '🤖' },
  { id: 'ratelimit' as const, label: 'Rate limit', icon: '⏱️' },
  { id: 'exceptions' as const, label: 'Исключения', icon: '🛡️' },
]

const visibleSections = computed(() =>
  isAdmin.value
    ? [...appearanceSection, ...adminSections, ...securitySections]
    : [...appearanceSection, ...securitySections],
)

const appearanceHint = computed(() => {
  const pref =
    themePref.value === 'light' ? 'светлая' : themePref.value === 'dark' ? 'тёмная' : 'как в системе'
  const now = themeResolved.value === 'light' ? 'светлая' : 'тёмная'
  return `${pref} (сейчас на экране: ${now})`
})

const sub = ref<SubId>('policies')

const busy = ref(false)
const err = ref('')
const ok = ref('')

const users = ref<(AuthUser & { active: boolean })[]>([])

const newUser = ref({
  username: '',
  password: '',
  display_name: '',
  email: '',
  role: 'viewer',
})

const authCfg = ref({
  local_auth_enabled: true,
  ldap_enabled: false,
  ldap_url: '',
  ldap_bind_dn: '',
  ldap_base_dn: '',
  ldap_user_filter: '(sAMAccountName=%s)',
  ldap_user_attr: 'sAMAccountName',
})
const ldapBindPassword = ref('')

const siem = ref({
  enabled: false,
  format: 'cef',
  host: '',
  port: 514,
  protocol: 'udp',
  tls: false,
  export_waf_logs: true,
  export_proxy_logs: true,
  export_audit_logs: false,
  device_vendor: 'FESS',
  device_product: 'WAF',
  device_version: '1.0',
  poll_interval_sec: 30,
})

watch(isAdmin, (admin) => {
  if (!admin && (sub.value === 'users' || sub.value === 'auth' || sub.value === 'siem' || sub.value === 'ai')) {
    sub.value = 'policies'
  }
})

async function loadAdmin() {
  if (!isAdmin.value) return
  busy.value = true
  err.value = ''
  ok.value = ''
  try {
    const [u, a, s] = await Promise.all([
      apiFetch<{ items: AuthUser[] }>(apiUrl('/users')),
      apiFetch<typeof authCfg.value>(apiUrl('/settings/auth')),
      apiFetch<typeof siem.value>(apiUrl('/settings/siem-export')),
    ])
    users.value = u.items as (AuthUser & { active: boolean })[]
    authCfg.value = a
    siem.value = s
    ldapBindPassword.value = ''
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

async function createUser() {
  busy.value = true
  err.value = ''
  ok.value = ''
  try {
    await apiFetch(apiUrl('/users'), { method: 'POST', body: newUser.value })
    ok.value = 'Пользователь создан'
    newUser.value = { username: '', password: '', display_name: '', email: '', role: 'viewer' }
    await loadAdmin()
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

async function saveUser(u: AuthUser & { active: boolean }) {
  try {
    await apiFetch(apiUrl(`/users/${u.id}`), {
      method: 'PUT',
      body: { display_name: u.display_name, email: u.email, role: u.role, active: u.active },
    })
    ok.value = 'Пользователь обновлён'
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  }
}

async function saveAuth() {
  busy.value = true
  err.value = ''
  ok.value = ''
  try {
    const body = { ...authCfg.value, ldap_bind_password: ldapBindPassword.value }
    await apiFetch(apiUrl('/settings/auth'), { method: 'PUT', body })
    ok.value = 'Настройки авторизации сохранены'
    ldapBindPassword.value = ''
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

async function saveSiem() {
  busy.value = true
  err.value = ''
  ok.value = ''
  try {
    await apiFetch(apiUrl('/settings/siem-export'), { method: 'PUT', body: siem.value })
    ok.value = 'Настройки SIEM сохранены'
  } catch (e: unknown) {
    const fe = e as { data?: { error?: string }; message?: string }
    err.value = fe?.data?.error || fe?.message || String(e)
  } finally {
    busy.value = false
  }
}

watch(sub, (id) => {
  if (isAdmin.value && (id === 'users' || id === 'auth' || id === 'siem' || id === 'ai')) {
    void loadAdmin()
  }
})

onMounted(() => {
  if (isAdmin.value && (sub.value === 'users' || sub.value === 'auth' || sub.value === 'siem' || sub.value === 'ai')) {
    void loadAdmin()
  }
})
</script>
