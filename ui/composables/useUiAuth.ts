const STORAGE_KEY = 'fence_ui_session'

export function useUiAuth() {
  const config = useRuntimeConfig()

  function gateEnabled(): boolean {
    const v = config.public.uiAuthEnabled
    if (v === false) return false
    const s = String(v ?? 'true').toLowerCase()
    return s !== '0' && s !== 'false' && s !== 'off'
  }

  const authed = useState<boolean>('fence-ui-authed', () => false)
  const ready = useState<boolean>('fence-ui-auth-ready', () => false)

  function init() {
    if (!import.meta.client) return
    if (!gateEnabled()) {
      authed.value = true
    } else {
      authed.value = sessionStorage.getItem(STORAGE_KEY) === '1'
    }
    ready.value = true
  }

  function login(username: string, password: string): { ok: true } | { ok: false; message: string } {
    const u = String(config.public.uiUser ?? 'admin').trim()
    const p = String(config.public.uiPassword ?? 'fence')
    if (username.trim() === u && password === p) {
      authed.value = true
      if (import.meta.client) sessionStorage.setItem(STORAGE_KEY, '1')
      return { ok: true }
    }
    return { ok: false, message: 'Неверный логин или пароль' }
  }

  function logout() {
    authed.value = false
    if (import.meta.client) sessionStorage.removeItem(STORAGE_KEY)
  }

  return { gateEnabled, authed, ready, init, login, logout }
}
