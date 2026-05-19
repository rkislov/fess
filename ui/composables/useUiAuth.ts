export type AuthUser = {
  id: string
  username: string
  display_name: string
  email: string
  role: 'admin' | 'operator' | 'viewer'
  auth_provider: string
  active: boolean
}

const SESSION_KEY = 'fence_ui_session'

export function useUiAuth() {
  const config = useRuntimeConfig()
  const { apiUrl } = useApi()
  const tokens = useAuthTokens()

  function gateEnabled(): boolean {
    const v = config.public.uiAuthEnabled
    if (v === false) return false
    const s = String(v ?? 'true').toLowerCase()
    return s !== '0' && s !== 'false' && s !== 'off'
  }

  const authed = useState<boolean>('fence-ui-authed', () => false)
  const ready = useState<boolean>('fence-ui-auth-ready', () => false)
  const user = useState<AuthUser | null>('fence-ui-user', () => null)

  async function loadMe(): Promise<boolean> {
    try {
      const res = await $fetch<{ user: AuthUser }>(apiUrl('/auth/me'), {
        headers: { Authorization: `Bearer ${tokens.getAccess()}` },
      })
      user.value = res.user
      authed.value = true
      if (import.meta.client) sessionStorage.setItem(SESSION_KEY, '1')
      return true
    } catch {
      return false
    }
  }

  async function init() {
    if (!import.meta.client) return
    if (!gateEnabled()) {
      authed.value = true
      user.value = { id: 'dev', username: 'dev', display_name: 'Dev', email: '', role: 'admin', auth_provider: 'local', active: true }
      ready.value = true
      return
    }
    const hasToken = !!tokens.getAccess()
    if (hasToken && (await loadMe())) {
      ready.value = true
      return
    }
    tokens.clearTokens()
    authed.value = false
    user.value = null
    sessionStorage.removeItem(SESSION_KEY)
    ready.value = true
  }

  async function login(
    username: string,
    password: string,
  ): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      const res = await $fetch<{
        tokens: { access_token: string; refresh_token: string }
        user: AuthUser
      }>(apiUrl('/auth/login'), {
        method: 'POST',
        body: { username: username.trim(), password },
      })
      tokens.setTokens(res.tokens.access_token, res.tokens.refresh_token)
      user.value = res.user
      authed.value = true
      if (import.meta.client) sessionStorage.setItem(SESSION_KEY, '1')
      return { ok: true }
    } catch (e: unknown) {
      const fe = e as { data?: { error?: string }; message?: string }
      return { ok: false, message: fe?.data?.error || fe?.message || 'Ошибка входа' }
    }
  }

  async function logout() {
    const refresh = tokens.getRefresh()
    try {
      const { apiFetch } = useAuthFetch()
      await apiFetch(apiUrl('/auth/logout'), {
        method: 'POST',
        body: { refresh_token: refresh },
      })
    } catch {
      /* ignore */
    }
    forceLogout()
  }

  function forceLogout() {
    authed.value = false
    user.value = null
    tokens.clearTokens()
    if (import.meta.client) sessionStorage.removeItem(SESSION_KEY)
  }

  function isAdmin() {
    return user.value?.role === 'admin'
  }

  return { gateEnabled, authed, ready, user, init, login, logout, forceLogout, isAdmin }
}
