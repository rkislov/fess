export function useApi() {
  const { apiUrl, apiFetch } = useAuthFetch()
  return { apiUrl, apiFetch }
}
