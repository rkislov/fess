export type RateLimitForm = {
  inherit: boolean
  enabled: boolean
  requests_per_window: number
  window_sec: number
  scope: string
}

export function defaultRateLimitForm(): RateLimitForm {
  return {
    inherit: true,
    enabled: true,
    requests_per_window: 120,
    window_sec: 60,
    scope: 'ip_host',
  }
}

export function rateLimitFromAPI(v: unknown): RateLimitForm {
  if (v == null) return defaultRateLimitForm()
  const o = v as Record<string, unknown>
  return {
    inherit: false,
    enabled: Boolean(o.enabled ?? true),
    requests_per_window: Number(o.requests_per_window ?? 120) || 120,
    window_sec: Number(o.window_sec ?? 60) || 60,
    scope: String(o.scope ?? 'ip_host') || 'ip_host',
  }
}

export function rateLimitToPayload(f: RateLimitForm): { inherit: true } | Record<string, unknown> {
  if (f.inherit) return { inherit: true }
  return {
    enabled: f.enabled,
    requests_per_window: f.requests_per_window,
    window_sec: f.window_sec,
    scope: f.scope,
  }
}
