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

export type XdpPeriod = 'hour' | 'day' | 'week'
export type XdpHistory = {
  period: XdpPeriod
  from: string
  to: string
  step_seconds: number
  points: { at: number; first_at: number; source: string; interface: string; coverage_seconds: number; rates: Record<string, number> }[]
}
export type XdpPoint = { at: number; rates: Record<string, number> | null }

// Preserve previous program runs. Separate restarts and unmeasured intervals
// instead of connecting them or inventing zero traffic.
export function xdpChartPoints(history: XdpHistory | null): XdpPoint[] {
  const result: XdpPoint[] = []
  let previous: XdpHistory['points'][number] | undefined
  for (const point of history?.points || []) {
    if (previous && (previous.source !== point.source || point.first_at - previous.at > 15000)) {
      result.push({ at: previous.at + 1, rates: null })
    }
    result.push({ at: point.at, rates: { ...point.rates, dropped: xdpDropped(point.rates) } })
    previous = point
  }
  return result
}
