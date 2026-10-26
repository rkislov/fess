import assert from 'node:assert/strict'
import test from 'node:test'
import { xdpChartPoints, xdpDropped, xdpHistoryTotals, xdpDropReasons } from '../utils/xdpStatistics.ts'
import type { XdpHistory } from '../utils/xdpStatistics.ts'

function history(points: XdpHistory['points']): XdpHistory {
  return { period: 'hour', from: '2026-10-23T10:00:00Z', to: '2026-10-23T11:00:00Z', step_seconds: 10, points }
}
function point(at: number, source = 'run1', first_at = at): XdpHistory['points'][number] {
  return { at, first_at, source, interface: 'ens3', coverage_seconds: 10, rates: { seen: 200, passed: 197, global_budget_drop: 1, temporary_block_drop: 2 } }
}

test('server history renders identically after a page reload', () => {
  const data = history([point(10000), point(20000)])
  assert.deepEqual(xdpChartPoints(data), xdpChartPoints(JSON.parse(JSON.stringify(data))))
  assert.equal(xdpChartPoints(data)[0]?.rates?.dropped, 3)
})

test('old program runs remain visible with a gap at restarts', () => {
  const points = xdpChartPoints(history([point(10000), point(20000, 'run2')]))
  assert.equal(points.length, 3)
  assert.equal(points[0]?.rates?.seen, 200)
  assert.equal(points[1]?.rates, null)
  assert.equal(points[2]?.rates?.seen, 200)
})

test('missing samples create gaps, while contiguous aggregated buckets connect', () => {
  assert.equal(xdpChartPoints(history([point(10000), point(40000)]))[1]?.rates, null)
  const aggregated = history([point(120000, 'run1', 10000), point(240000, 'run1', 130000)])
  aggregated.period = 'day'; aggregated.step_seconds = 120
  assert.equal(xdpChartPoints(aggregated).length, 2)
})

test('empty history is not fabricated zero traffic', () => {
  assert.deepEqual(xdpChartPoints(null), [])
  assert.deepEqual(xdpChartPoints(history([])), [])
})

test('drop totals exclude traffic and malformed packets passed to the stack', () => {
  assert.equal(xdpDropped({ seen: 999, passed: 900, malformed_pass: 20, protected_packets: 200, icmp_ping_drop: 3, cidr_drop: 2, malformed_drop: 4 }), 9)
})

test('period totals integrate actual coverage, include previous runs and every drop reason', () => {
  const a = point(10000)
  const b = { ...point(600000, 'run2'), coverage_seconds: 20 }
  // Two measured intervals separated by downtime; the second has twice the
  // coverage. All reason counts sum to seen - passed, including after restart.
  a.rates = { seen: 100, passed: 72, frame_bytes: 100000, protected_packets: 60, protected_bytes: 60000, protected_syn: 2, icmp_echo: 3, malformed_pass: 4 }
  b.rates = { seen: 200, passed: 144, frame_bytes: 200000, protected_packets: 120, protected_bytes: 120000, protected_syn: 4, icmp_echo: 6, malformed_pass: 8 }
  xdpDropReasons.forEach(({ key }, i) => {
    Object.assign(a.rates, { [key]: i + 1 })
    Object.assign(b.rates, { [key]: 2 * (i + 1) })
  })
  const totals = xdpHistoryTotals(history([a, b]))!
  assert.equal(totals.coverageSeconds, 30)
  assert.equal(totals.counters.seen, 5000)
  assert.equal(totals.counters.passed, 3600)
  assert.equal(totals.counters.frame_bytes, 5000000)
  assert.equal(totals.counters.protected_packets, 3000)
  assert.equal(totals.counters.protected_bytes, 3000000)
  assert.equal(totals.counters.protected_syn, 100)
  assert.equal(totals.counters.icmp_echo, 150)
  assert.equal(totals.counters.malformed_pass, 200)
  assert.equal(totals.rates.seen, 5000 / 30)
  xdpDropReasons.forEach(({ key }, i) => assert.equal(totals.counters[key], 50 * (i + 1)))
  assert.equal(xdpDropped(totals.counters), 1400)
  assert.equal(totals.counters.seen! - totals.counters.passed!, xdpDropped(totals.counters))
  assert.deepEqual(xdpHistoryTotals(JSON.parse(JSON.stringify(history([a, b])))), totals)
})

test('hour, day and week totals use only their selected history and ignore bucket size', () => {
  const hour = history([{ ...point(10000), coverage_seconds: 3, rates: { seen: 2 / 3 } }])
  const day: XdpHistory = { ...history([
    { ...point(120000), coverage_seconds: 30, rates: { seen: 7000 / 30 } },
  ]), period: 'day', step_seconds: 120 }
  const week: XdpHistory = { ...day, period: 'week', step_seconds: 600, points: [
    ...day.points, { ...point(600000, 'run2'), coverage_seconds: 20, rates: { seen: 50 } },
  ] }
  assert.equal(xdpHistoryTotals(hour)?.counters.seen, 2)
  assert.equal(xdpHistoryTotals(day)?.counters.seen, 7000)
  assert.equal(xdpHistoryTotals(week)?.counters.seen, 8000)
})

test('missing history is unavailable while an observed zero is a real zero', () => {
  assert.equal(xdpHistoryTotals(null), null)
  assert.equal(xdpHistoryTotals(history([])), null)
  assert.equal(xdpHistoryTotals(history([{ ...point(10000), rates: { seen: 0 } }]))?.counters.seen, 0)
})
