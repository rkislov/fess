const ACCESS_KEY = 'fence_access_token'
const REFRESH_KEY = 'fence_refresh_token'

export function useAuthTokens() {
  function getAccess(): string {
    if (!import.meta.client) return ''
    return sessionStorage.getItem(ACCESS_KEY) || ''
  }

  function getRefresh(): string {
    if (!import.meta.client) return ''
    return sessionStorage.getItem(REFRESH_KEY) || ''
  }

  function setTokens(access: string, refresh: string) {
    if (!import.meta.client) return
    sessionStorage.setItem(ACCESS_KEY, access)
    sessionStorage.setItem(REFRESH_KEY, refresh)
  }

  function clearTokens() {
    if (!import.meta.client) return
    sessionStorage.removeItem(ACCESS_KEY)
    sessionStorage.removeItem(REFRESH_KEY)
  }

  return { getAccess, getRefresh, setTokens, clearTokens }
}
