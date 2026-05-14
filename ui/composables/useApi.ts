export function useApi() {
  const config = useRuntimeConfig()
  const base = (config.public.apiBase as string).replace(/\/$/, '')

  function apiUrl(path: string) {
    const p = path.startsWith('/') ? path : `/${path}`
    return `${base}${p}`
  }

  return { apiUrl }
}
