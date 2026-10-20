const LOGIN_LOG_KEY = 'fence_ui_login_log'

export type PanelLoginEntry = { t: string; user: string; ok: boolean }

export function appendPanelLoginEntry(username: string, ok: boolean) {
  if (!import.meta.client) return
  try {
    const prev = sessionStorage.getItem(LOGIN_LOG_KEY)
    const arr: PanelLoginEntry[] = prev ? JSON.parse(prev) : []
    arr.unshift({ t: new Date().toISOString(), user: username.trim() || '—', ok })
    sessionStorage.setItem(LOGIN_LOG_KEY, JSON.stringify(arr.slice(0, 200)))
  } catch {
    /* ignore */
  }
}

export function readPanelLoginLog(): PanelLoginEntry[] {
  if (!import.meta.client) return []
  try {
    const raw = sessionStorage.getItem(LOGIN_LOG_KEY)
    if (!raw) return []
    const arr = JSON.parse(raw) as PanelLoginEntry[]
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

export function clearPanelLoginLog() {
  if (!import.meta.client) return
  sessionStorage.removeItem(LOGIN_LOG_KEY)
}
