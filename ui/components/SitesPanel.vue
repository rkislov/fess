<template>
  <div class="space-y-6">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <div class="flex flex-wrap gap-2">
      <button type="button" class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700" :disabled="busy" @click="loadSites">
        Reload sites
      </button>
    </div>

    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Sites</h2>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          v-for="s in sites"
          :key="s.id"
          type="button"
          class="rounded-lg border px-3 py-1.5 text-sm transition"
          :class="
            selectedId === s.id
              ? 'border-sky-500 bg-sky-950/50 text-sky-100'
              : 'border-slate-700 bg-slate-800/80 text-slate-200 hover:border-slate-500'
          "
          @click="selectSite(s)"
        >
          {{ s.name }} <span class="text-slate-500">({{ s.host_pattern }})</span>
        </button>
      </div>

      <div class="mt-6 grid gap-4 border-t border-slate-800 pt-6 md:grid-cols-2">
        <div>
          <h3 class="text-sm font-medium text-slate-300">New site</h3>
          <div class="mt-2 space-y-2">
            <input v-model="newSite.name" placeholder="Name" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <input
              v-model="newSite.host_pattern"
              placeholder="Host pattern e.g. *.example.com"
              class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            />
            <input v-model.number="newSite.priority" type="number" placeholder="Priority (default 100)" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <label class="flex items-center gap-2 text-sm text-slate-400">
              <input v-model="newSite.enabled" type="checkbox" class="rounded border-slate-600" />
              Enabled
            </label>
            <div>
              <label class="text-xs text-slate-500">WAF policy (optional)</label>
              <select v-model="newSite.policy_id" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <option value="">All enabled policies (default)</option>
                <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
              </select>
            </div>
            <button type="button" class="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500" :disabled="busy" @click="createSite">
              Create site
            </button>
          </div>
        </div>

        <div v-if="selected">
          <h3 class="text-sm font-medium text-slate-300">Edit site</h3>
          <div class="mt-2 space-y-2">
            <input v-model="edit.name" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <input v-model="edit.host_pattern" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <input v-model.number="edit.priority" type="number" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
            <label class="flex items-center gap-2 text-sm text-slate-400">
              <input v-model="edit.enabled" type="checkbox" class="rounded border-slate-600" />
              Enabled
            </label>
            <div>
              <label class="text-xs text-slate-500">WAF policy for this host</label>
              <select
                v-model="edit.policy_id"
                class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
              >
                <option value="">All enabled policies (default)</option>
                <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
              </select>
              <p class="mt-1 text-xs text-slate-500">
                Only that policy’s rules apply for matching <code class="text-slate-400">Host</code>. Leave empty to
                evaluate every enabled policy by priority.
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <button type="button" class="rounded-lg bg-slate-700 px-3 py-2 text-sm hover:bg-slate-600" :disabled="busy" @click="saveSite">Save</button>
              <button type="button" class="rounded-lg border border-rose-800 px-3 py-2 text-sm text-rose-300 hover:bg-rose-950/50" :disabled="busy" @click="deleteSite">
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section v-if="sites.length" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <h2 class="text-lg font-semibold text-white">Backends</h2>
      <p class="mt-1 text-sm text-slate-400">
        Upstream origins for the selected site (gateway picks the first enabled backend by priority).
      </p>
      <div class="mt-4 flex flex-wrap items-center gap-3">
        <label class="text-sm text-slate-400">Site</label>
        <select
          v-model="selectedId"
          class="min-w-[12rem] rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          @change="onSiteSelectChange"
        >
          <option disabled value="">— choose —</option>
          <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }} ({{ s.host_pattern }})</option>
        </select>
      </div>

      <template v-if="selected">
        <p class="mt-2 text-sm text-slate-500">
          Editing: <strong class="text-slate-300">{{ selected.name }}</strong>
        </p>

      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-800 text-slate-500">
              <th class="py-2 pr-4">Name</th>
              <th class="py-2 pr-4">Base URL</th>
              <th class="py-2 pr-4">Priority</th>
              <th class="py-2">On</th>
              <th class="py-2" />
            </tr>
          </thead>
          <tbody>
            <tr v-if="!backends.length">
              <td colspan="5" class="py-6 text-center text-slate-500">No backends for this site — add one below.</td>
            </tr>
            <tr v-for="b in backends" :key="b.id" class="border-b border-slate-800/80">
              <td class="py-2 pr-4">
                <input v-model="b.name" class="w-full min-w-[100px] rounded border border-slate-700 bg-slate-950 px-2 py-1" />
              </td>
              <td class="py-2 pr-4">
                <input v-model="b.base_url" class="w-full min-w-[180px] rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs" />
              </td>
              <td class="py-2 pr-4">
                <input v-model.number="b.priority" type="number" class="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1" />
              </td>
              <td class="py-2">
                <input v-model="b.enabled" type="checkbox" class="rounded border-slate-600" />
              </td>
              <td class="py-2">
                <button type="button" class="text-sky-400 hover:underline" @click="saveBackend(b)">Save</button>
                <button type="button" class="ml-2 text-rose-400 hover:underline" @click="removeBackend(b)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-6 border-t border-slate-800 pt-6">
        <h3 class="text-sm font-medium text-slate-300">New backend</h3>
        <div class="mt-2 flex flex-wrap gap-2">
          <input v-model="newBackend.name" placeholder="Name" class="min-w-[120px] flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          <input
            v-model="newBackend.base_url"
            placeholder="http://upstream:8080"
            class="min-w-[200px] flex-[2] rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono"
          />
          <input v-model.number="newBackend.priority" type="number" placeholder="Priority" class="w-24 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
          <button type="button" class="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500" :disabled="busy" @click="addBackend">Add</button>
        </div>
      </div>
      </template>
      <p v-else class="mt-4 text-sm text-slate-500">Select a site in the dropdown to list and edit backends.</p>
    </section>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl } = useApi()

type Site = {
  id: string
  name: string
  host_pattern: string
  priority: number
  enabled: boolean
  policy_id: string
}
type Backend = { id: string; name: string; base_url: string; priority: number; enabled: boolean }

const err = ref('')
const ok = ref('')
const busy = ref(false)
const sites = ref<Site[]>([])
const selectedId = ref('')
const selected = computed(() => sites.value.find((s) => s.id === selectedId.value) ?? null)
const policies = ref<{ id: string; name: string }[]>([])
const edit = reactive({ name: '', host_pattern: '', priority: 100, enabled: true, policy_id: '' })
const backends = ref<Backend[]>([])

const newSite = reactive({ name: '', host_pattern: '', priority: 0, enabled: true, policy_id: '' })
const newBackend = reactive({ name: '', base_url: '', priority: 0 })

function flashErr(e: unknown) {
  ok.value = ''
  const fe = e as FetchError<{ error?: string }>
  err.value = fe?.data?.error || fe?.message || String(e)
}

function flashOk(msg: string) {
  err.value = ''
  ok.value = msg
  setTimeout(() => {
    ok.value = ''
  }, 4000)
}

function normSite(raw: Record<string, unknown>): Site {
  return {
    id: String(raw.id ?? raw.ID),
    name: String(raw.name ?? raw.Name),
    host_pattern: String(raw.host_pattern ?? raw.HostPattern),
    priority: Number(raw.priority ?? raw.Priority),
    enabled: Boolean(raw.enabled ?? raw.Enabled),
    policy_id: String(raw.policy_id ?? raw.PolicyID ?? ''),
  }
}

function normBackend(raw: Record<string, unknown>): Backend {
  return {
    id: String(raw.id ?? raw.ID),
    name: String(raw.name ?? raw.Name),
    base_url: String(raw.base_url ?? raw.BaseURL),
    priority: Number(raw.priority ?? raw.Priority),
    enabled: Boolean(raw.enabled ?? raw.Enabled),
  }
}

async function loadPolicies() {
  const data = await $fetch<{ items: { id: string; name: string }[] }>(apiUrl('/policies'))
  policies.value = data.items || []
}

function pickDefaultSite(list: Site[]): Site | null {
  if (!list.length) return null
  const star = list.find((s) => s.host_pattern === '*')
  if (star) return star
  const named = list.find((s) => s.name === 'default')
  if (named) return named
  return list[0] ?? null
}

async function loadSites() {
  busy.value = true
  err.value = ''
  const prevId = selectedId.value
  try {
    const data = await $fetch<{ items: Record<string, unknown>[] }>(apiUrl('/sites'))
    sites.value = (data.items || []).map(normSite)
    const still = prevId && sites.value.some((s) => s.id === prevId)
    if (still) {
      applySelection(prevId)
    } else if (sites.value.length) {
      const pick = pickDefaultSite(sites.value)
      if (pick) applySelection(pick.id)
    } else {
      selectedId.value = ''
      backends.value = []
    }
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function loadBackends(siteId: string) {
  const data = await $fetch<{ items: Record<string, unknown>[] }>(apiUrl(`/sites/${siteId}/backends`))
  backends.value = (data.items || []).map(normBackend)
}

function applySelection(siteId: string) {
  const s = sites.value.find((x) => x.id === siteId)
  if (!s) return
  selectedId.value = siteId
  edit.name = s.name
  edit.host_pattern = s.host_pattern
  edit.priority = s.priority
  edit.enabled = s.enabled
  edit.policy_id = s.policy_id || ''
  loadBackends(siteId).catch(flashErr)
}

function selectSite(s: Site) {
  applySelection(s.id)
}

function onSiteSelectChange() {
  const id = selectedId.value
  if (!id) {
    backends.value = []
    return
  }
  applySelection(id)
}

async function createSite() {
  busy.value = true
  err.value = ''
  try {
    const res = await $fetch<{ id: string }>(apiUrl('/sites'), {
      method: 'POST',
      body: {
        name: newSite.name,
        host_pattern: newSite.host_pattern,
        priority: newSite.priority || undefined,
        enabled: newSite.enabled,
        policy_id: newSite.policy_id || undefined,
      },
    })
    newSite.name = ''
    newSite.host_pattern = ''
    await loadSites()
    if (res.id) applySelection(res.id)
    flashOk('Site created')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveSite() {
  if (!selected.value) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}`), {
      method: 'PUT',
      body: {
        name: edit.name,
        host_pattern: edit.host_pattern,
        priority: edit.priority,
        enabled: edit.enabled,
        policy_id: edit.policy_id || '',
      },
    })
    await loadSites()
    flashOk('Site saved')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function deleteSite() {
  if (!selected.value) return
  if (!confirm('Delete this site and its backends?')) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}`), { method: 'DELETE' })
    selectedId.value = ''
    backends.value = []
    await loadSites()
    flashOk('Site deleted')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveBackend(b: Backend) {
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backends/${b.id}`), {
      method: 'PUT',
      body: {
        name: b.name,
        base_url: b.base_url,
        priority: b.priority,
        enabled: b.enabled,
      },
    })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Backend saved')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function removeBackend(b: Backend) {
  if (!confirm('Delete this backend?')) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backends/${b.id}`), { method: 'DELETE' })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Backend deleted')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function addBackend() {
  if (!selected.value) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}/backends`), {
      method: 'POST',
      body: {
        name: newBackend.name,
        base_url: newBackend.base_url,
        priority: newBackend.priority || undefined,
        enabled: true,
      },
    })
    newBackend.name = ''
    newBackend.base_url = ''
    await loadBackends(selected.value.id)
    flashOk('Backend added')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  loadPolicies().catch(flashErr)
  loadSites().catch(flashErr)
})
</script>
