import type { FetchError } from 'ofetch'

export type WafProfile = {
  id: string
  version: string
  sha256: string
  title: string
  rule_count: number
  policy_id?: string
}

export function profileChoice(profile: WafProfile) {
  return `feed:${profile.id}:${profile.version}:${profile.sha256}`
}

export function useWafProfiles() {
  const { apiUrl, apiFetch } = useApi()
  const profiles = ref<WafProfile[]>([])
  const loading = ref(false)
  const catalogError = ref('')

  async function loadCatalog() {
    if (loading.value) return
    loading.value = true
    catalogError.value = ''
    try {
      const catalog = await apiFetch<{ packs: WafProfile[] }>(apiUrl('/waf-feed/catalog'))
      profiles.value = catalog.packs
    } catch (e) {
      profiles.value = []
      const err = e as FetchError<{ error: string }>
      catalogError.value = err.data?.error || err.message || 'Ошибка запроса'
    } finally {
      loading.value = false
    }
  }

  async function policyFor(profile: WafProfile): Promise<string> {
    if (profile.policy_id) return profile.policy_id
    const { policy_ids } = await apiFetch<{ policy_ids: string[] }>(apiUrl('/waf-feed/import'), {
      method: 'POST',
      body: { id: profile.id, version: profile.version, sha256: profile.sha256 },
    })
    if (!policy_ids[0]) throw new Error('Не удалось получить политику для заготовки')
    profile.policy_id = policy_ids[0]
    return profile.policy_id
  }

  return { profiles, loading, catalogError, loadCatalog, policyFor }
}
