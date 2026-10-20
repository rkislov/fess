/** Append shared log search / time window query params. */
export function appendLogQueryBase(
  params: URLSearchParams,
  opts: { q?: string; hours?: number },
) {
  const q = opts.q?.trim()
  if (q) params.set('q', q)
  if (opts.hours != null && opts.hours >= 0) {
    params.set('hours', String(opts.hours))
  }
}

export function appendIfSet(params: URLSearchParams, key: string, value: string | undefined) {
  const v = value?.trim()
  if (v) params.set(key, v)
}
