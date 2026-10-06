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

function publicApiBase() {
  const config = useRuntimeConfig()
  return (config.public.apiBase as string).replace(/\/$/, '')
}

function publicApiUrl(path: string) {
  const p = path.startsWith('/') ? path : `/${path}`
  return `${publicApiBase()}${p}`
}

export function useUiAuth() {
  const config = useRuntimeConfig()
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

  const hasAccessToken = computed(() => !!tokens.getAccess())

  async function loadMe(): Promise<boolean> {
    const access = tokens.getAccess()
    if (!access) return false
    try {
      const res = await $fetch<{ user: AuthUser }>(publicApiUrl('/auth/me'), {
        headers: { Authorization: `Bearer ${access}` },
      })
      user.value = res.user
      authed.value = true
      if (import.meta.client) sessionStorage.setItem(SESSION_KEY, '1')
      return true
    } catch {
      return false
    }
  }

  async function loginWithCredentials(
    username: string,
    password: string,
  ): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      const res = await $fetch<{
        tokens: { access_token: string; refresh_token: string }
        user: AuthUser
      }>(publicApiUrl('/auth/login'), {
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

  async function bootstrapEnvLogin(): Promise<boolean> {
    const u = String(config.public.uiUser ?? 'admin').trim()
    const p = String(config.public.uiPassword ?? 'fessfess')
    const r = await loginWithCredentials(u, p)
    return r.ok
  }

  async function init() {
    if (!import.meta.client) return

    // Старый флаг сессии без JWT — сбрасываем.
    if (sessionStorage.getItem(SESSION_KEY) && !tokens.getAccess()) {
      sessionStorage.removeItem(SESSION_KEY)
    }

    if (tokens.getAccess() && (await loadMe())) {
      ready.value = true
      return
    }

    tokens.clearTokens()
    authed.value = false
    user.value = null
    sessionStorage.removeItem(SESSION_KEY)

    // UI-gate выкл.: тихий вход локальным пользователем из env (admin/fessfess).
    if (!gateEnabled()) {
      await bootstrapEnvLogin()
    }

    ready.value = true
  }

  async function login(
    username: string,
    password: string,
  ): Promise<{ ok: true } | { ok: false; message: string }> {
    return loginWithCredentials(username, password)
  }

  async function logout() {
    const refresh = tokens.getRefresh()
    const access = tokens.getAccess()
    try {
      if (access) {
        await $fetch(publicApiUrl('/auth/logout'), {
          method: 'POST',
          headers: { Authorization: `Bearer ${access}` },
          body: { refresh_token: refresh },
        })
      }
    } catch {
      /* ignore */
    }
    forceLogout()
  }

  function forceLogout() {
    authed.value = false
    user.value = null
    tokens.clearTokens()
    if (import.meta.client) {
      sessionStorage.removeItem(SESSION_KEY)
    }
  }

  function isAdmin() {
    return user.value?.role === 'admin'
  }

  /** Показывать основной UI только при валидном access token. */
  function canUseApp() {
    return authed.value && hasAccessToken.value
  }

  return {
    gateEnabled,
    authed,
    ready,
    user,
    hasAccessToken,
    canUseApp,
    init,
    login,
    logout,
    forceLogout,
    isAdmin,
  }
}
