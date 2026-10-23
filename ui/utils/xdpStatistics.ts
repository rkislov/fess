export type XdpStatistics = {
  pid: number
  program_id: number
  interface: string
  started_at: string
  sampled_at: string
  interval_seconds: number
  stale: boolean
  counters: Record<string, number>
  rates: Record<string, number>
}

export const xdpDropReasons = [
  { key: 'cidr_drop', label: 'CIDR deny' },
  { key: 'rate_drop', label: 'Лимит на IP' },
  { key: 'global_budget_drop', label: 'Общий бюджет' },
  { key: 'icmp_ping_drop', label: 'ICMP Ping Flood' },
  { key: 'malformed_drop', label: 'Некорректные пакеты' },
  { key: 'temporary_block_drop', label: 'Временные баны WAF' },
  { key: 'fragment_drop', label: 'IP-фрагменты' },
]

export function xdpDropped(counters: Record<string, number>) {
  return xdpDropReasons.reduce((sum, reason) => sum + (counters[reason.key] || 0), 0)
}

export type XdpPoint = { at: number; rates: Record<string, number> | null }
export type XdpHistory = { source: string; points: XdpPoint[] }
export const xdpHistoryWindow = 15 * 60 * 1000

// Snapshot timestamps, rather than polling times, deduplicate the controller's
// ten-second samples. A new program must never connect to the previous series.
export function appendXdpSample(history: XdpHistory, sample: XdpStatistics): XdpHistory {
  const source = `${sample.interface}/${sample.pid}/${sample.program_id}/${sample.started_at}`
  const points = source === history.source ? history.points : []
  const at = Date.parse(sample.sampled_at)
  if (!Number.isFinite(at) || sample.stale || sample.interval_seconds <= 0) return { source, points }
  const last = points.at(-1)
  if (last && at <= last.at) return { source, points }
  const next = points.filter(point => point.at >= at - xdpHistoryWindow)
  if (last && at - last.at > 15000 && next.length) next.push({ at: last.at + 1, rates: null })
  next.push({ at, rates: { ...sample.rates, dropped: xdpDropped(sample.rates) } })
  return { source, points: next.slice(-180) }
}
