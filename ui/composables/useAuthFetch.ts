import type { FetchOptions } from 'ofetch'

function apiBaseUrl() {
  const config = useRuntimeConfig()
  return (config.public.apiBase as string).replace(/\/$/, '')
}

export function useAuthFetch() {
  const tokens = useAuthTokens()
  const authed = useState<boolean>('fence-ui-authed', () => false)
  const user = useState<unknown>('fence-ui-user', () => null)

  function apiUrl(path: string) {
    const p = path.startsWith('/') ? path : `/${path}`
    return `${apiBaseUrl()}${p}`
  }

  let refreshPromise: Promise<boolean> | null = null

  async function tryRefresh(): Promise<boolean> {
    const refresh = tokens.getRefresh()
    if (!refresh) return false
    if (!refreshPromise) {
      refreshPromise = (async () => {
        try {
          const res = await $fetch<{ tokens: { access_token: string; refresh_token: string } }>(
            apiUrl('/auth/refresh'),
            { method: 'POST', body: { refresh_token: refresh } },
          )
          tokens.setTokens(res.tokens.access_token, res.tokens.refresh_token)
          return true
        } catch {
          tokens.clearTokens()
          authed.value = false
          user.value = null
          if (import.meta.client) sessionStorage.removeItem('fence_ui_session')
          return false
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  async function apiFetch<T>(url: string, opts: FetchOptions = {}): Promise<T> {
    const headers = new Headers(opts.headers as HeadersInit | undefined)
    const access = tokens.getAccess()
    if (access) headers.set('Authorization', `Bearer ${access}`)

    try {
      return await $fetch<T>(url, { ...opts, headers })
    } catch (e: unknown) {
      const fe = e as { status?: number; statusCode?: number }
      const status = fe?.status ?? fe?.statusCode
      if (status === 401 && tokens.getRefresh()) {
        const ok = await tryRefresh()
        if (ok) {
          const retryHeaders = new Headers(opts.headers as HeadersInit | undefined)
          retryHeaders.set('Authorization', `Bearer ${tokens.getAccess()}`)
          return await $fetch<T>(url, { ...opts, headers: retryHeaders })
        }
      }
      throw e
    }
  }

  return { apiUrl, apiFetch }
}
