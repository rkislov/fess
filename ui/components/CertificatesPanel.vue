<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h2 class="text-lg font-semibold text-white">Удостоверяющий центр</h2>
      <p class="mt-1 text-sm text-slate-400">
        Сертификаты для HTTPS на шлюзе: загрузка PEM, самоподписанные для стенда и выпуск через ACME (Let’s Encrypt, HTTP-01 на порту 80).
      </p>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">ACME</h3>
      <p class="mt-1 text-xs text-slate-500">
        Шлюз должен быть доступен с интернета на TCP 80 по именам из заказа. Wildcard через HTTP-01 недоступен.
      </p>
      <div class="mt-4 grid gap-3 sm:grid-cols-2">
        <label class="block text-xs text-slate-400">
          Directory URL
          <select v-model="acme.directory_url" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
            <option value="https://acme-v02.api.letsencrypt.org/directory">Let’s Encrypt</option>
            <option value="https://acme-staging-v02.api.letsencrypt.org/directory">Let’s Encrypt Staging</option>
            <option value="custom">Другой…</option>
          </select>
        </label>
        <label v-if="acmeDirCustom" class="block text-xs text-slate-400">
          Свой directory
          <input v-model="acmeCustomDir" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" />
        </label>
        <label class="block text-xs text-slate-400">
          Email аккаунта
          <input v-model="acme.email" type="email" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        </label>
        <label class="block text-xs text-slate-400">
          Продлевать за (дней)
          <input v-model.number="acme.renew_before_days" type="number" min="1" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        </label>
        <label class="flex items-center gap-2 text-sm text-slate-300 sm:col-span-2">
          <input v-model="acme.tos_agreed" type="checkbox" class="rounded border-slate-600" />
          Согласен с условиями выбранного ACME CA
        </label>
      </div>
      <p class="mt-2 text-xs text-slate-500">
        Аккаунт: <span v-if="acme.has_account_key" class="text-emerald-400">ключ сохранён</span><span v-else>ещё не создан</span>
      </p>
      <button type="button" class="mt-4 rounded-lg bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-600" :disabled="busy" @click="saveAcme">
        Сохранить ACME
      </button>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <h3 class="text-sm font-semibold text-white">Выпустить или загрузить</h3>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          v-for="m in modes"
          :key="m.id"
          type="button"
          class="rounded-lg px-3 py-1.5 text-sm"
          :class="mode === m.id ? 'bg-teal-600 text-white' : 'bg-slate-800 text-slate-300'"
          @click="mode = m.id"
        >
          {{ m.label }}
        </button>
      </div>
      <div class="mt-4 grid gap-3">
        <label class="block text-xs text-slate-400">
          Имя
          <input v-model="form.name" placeholder="example.com" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        </label>
        <label class="block text-xs text-slate-400">
          Имена (по одному в строке)
          <textarea v-model="form.domainsText" rows="3" placeholder="example.com&#10;www.example.com" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" />
        </label>
        <template v-if="mode === 'manual'">
          <textarea v-model="form.cert_pem" rows="5" placeholder="-----BEGIN CERTIFICATE-----" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" />
          <textarea v-model="form.key_pem" rows="4" placeholder="-----BEGIN PRIVATE KEY-----" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" />
        </template>
        <label v-if="mode === 'self_signed'" class="block text-xs text-slate-400">
          Срок, дней
          <input v-model.number="form.valid_days" type="number" min="1" class="mt-1 w-40 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        </label>
        <label class="block text-xs text-slate-400">
          Привязать к сайтам
          <select v-model="form.site_ids" multiple class="mt-1 h-28 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
            <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }} ({{ s.host_pattern }})</option>
          </select>
        </label>
        <button type="button" class="w-fit rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500" :disabled="busy" @click="createCert">
          {{ mode === 'acme' ? 'Выпустить ACME' : mode === 'self_signed' ? 'Сгенерировать' : 'Загрузить' }}
        </button>
      </div>
    </section>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex items-center justify-between gap-2">
        <h3 class="text-sm font-semibold text-white">Сертификаты</h3>
        <button type="button" class="rounded-lg bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700" :disabled="busy" @click="load">Обновить</button>
      </div>
      <p v-if="!items.length && !busy" class="mt-4 text-sm text-slate-500">Пока нет записей.</p>
      <ul class="mt-4 space-y-3">
        <li v-for="c in items" :key="c.id" class="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p class="font-medium text-white">{{ c.name }}</p>
              <p class="mt-1 font-mono text-xs text-slate-500">{{ (c.domains || []).join(', ') || '—' }}</p>
              <p class="mt-1 text-xs text-slate-500">
                {{ sourceLabel(c.source) }}
                · <span :class="statusClass(c)">{{ c.status }}</span>
                <span v-if="c.not_after"> · до {{ fmtTs(c.not_after) }}</span>
              </p>
              <p v-if="c.sites?.length" class="mt-1 text-xs text-slate-400">
                Сайты: {{ c.sites.map((s) => s.host_pattern).join(', ') }}
              </p>
              <p v-if="c.last_error" class="mt-1 text-xs text-rose-300">{{ c.last_error }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                v-if="c.source === 'acme'"
                type="button"
                class="rounded-lg bg-slate-800 px-3 py-1.5 text-xs hover:bg-slate-700"
                :disabled="busy"
                @click="renew(c.id)"
              >
                Продлить
              </button>
              <button type="button" class="rounded-lg border border-rose-800/70 px-3 py-1.5 text-xs text-rose-300" :disabled="busy" @click="remove(c)">
                Удалить
              </button>
            </div>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl, apiFetch } = useApi()

type Cert = {
  id: string
  name: string
  source: string
  domains: string[]
  status: string
  not_after?: string
  last_error?: string
  sites: { id: string; name: string; host_pattern: string }[]
}

const LE = 'https://acme-v02.api.letsencrypt.org/directory'
const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'

const items = ref<Cert[]>([])
const sites = ref<{ id: string; name: string; host_pattern: string }[]>([])
const busy = ref(false)
const err = ref('')
const ok = ref('')
const mode = ref<'acme' | 'self_signed' | 'manual'>('acme')
const modes = [
  { id: 'acme' as const, label: 'Let’s Encrypt' },
  { id: 'self_signed' as const, label: 'Самоподписанный' },
  { id: 'manual' as const, label: 'Загрузить PEM' },
]
const form = reactive({
  name: '',
  domainsText: '',
  cert_pem: '',
  key_pem: '',
  valid_days: 365,
  site_ids: [] as string[],
})
const acme = reactive({
  directory_url: LE,
  email: '',
  tos_agreed: false,
  renew_before_days: 30,
  has_account_key: false,
})
const acmeCustomDir = ref('')
const acmeDirCustom = computed(() => acme.directory_url !== LE && acme.directory_url !== STAGING)

function sourceLabel(s: string) {
  if (s === 'acme') return 'ACME'
  if (s === 'self_signed') return 'самоподписанный'
  return 'загрузка'
}
function statusClass(c: Cert) {
  if (c.status === 'issued') return 'text-emerald-400'
  if (c.status === 'error') return 'text-rose-400'
  return 'text-amber-300'
}
function fmtTs(iso: string) {
  try {
    return new Date(iso).toLocaleString('ru-RU')
  } catch {
    return iso
  }
}
function flashErr(e: unknown) {
  const fe = e as FetchError
  err.value = (fe?.data as { error?: string })?.error || (e as Error)?.message || String(e)
  ok.value = ''
}
function domains() {
  return form.domainsText
    .split(/\n|,/)
    .map((s) => s.trim())
    .filter(Boolean)
}

async function load() {
  busy.value = true
  err.value = ''
  try {
    const [certs, siteData, acmeData] = await Promise.all([
      apiFetch<{ items: Cert[] }>(apiUrl('/certificates')),
      apiFetch<{ items: { id: string; name: string; host_pattern: string }[] }>(apiUrl('/sites')),
      apiFetch<typeof acme>(apiUrl('/settings/acme')),
    ])
    items.value = certs.items || []
    sites.value = siteData.items || []
    Object.assign(acme, acmeData)
    if (acme.directory_url !== LE && acme.directory_url !== STAGING) {
      acmeCustomDir.value = acme.directory_url
      acme.directory_url = 'custom'
    }
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveAcme() {
  busy.value = true
  err.value = ''
  try {
    let dir = acme.directory_url
    if (dir === 'custom') dir = acmeCustomDir.value.trim()
    await apiFetch(apiUrl('/settings/acme'), {
      method: 'PUT',
      body: {
        directory_url: dir,
        email: acme.email,
        tos_agreed: acme.tos_agreed,
        renew_before_days: acme.renew_before_days,
      },
    })
    ok.value = 'Настройки ACME сохранены'
    await load()
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function createCert() {
  busy.value = true
  err.value = ''
  ok.value = ''
  try {
    await apiFetch(apiUrl('/certificates'), {
      method: 'POST',
      body: {
        name: form.name.trim(),
        source: mode.value,
        domains: domains(),
        cert_pem: form.cert_pem,
        key_pem: form.key_pem,
        valid_days: form.valid_days,
        site_ids: form.site_ids,
        auto_renew: mode.value === 'acme',
      },
    })
    form.name = ''
    form.domainsText = ''
    form.cert_pem = ''
    form.key_pem = ''
    form.site_ids = []
    ok.value = 'Сертификат сохранён'
    await load()
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function renew(id: string) {
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl(`/certificates/${id}/renew`), { method: 'POST' })
    ok.value = 'Продление запущено'
    await load()
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function remove(c: Cert) {
  if (!confirm(`Удалить сертификат «${c.name}»?`)) return
  busy.value = true
  err.value = ''
  try {
    await apiFetch(apiUrl(`/certificates/${c.id}`), { method: 'DELETE' })
    ok.value = 'Удалено'
    await load()
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  load()
})
</script>
