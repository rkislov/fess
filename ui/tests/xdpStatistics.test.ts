import assert from 'node:assert/strict'
import test from 'node:test'
import { xdpChartPoints, xdpDropped } from '../utils/xdpStatistics.ts'
import type { XdpHistory } from '../utils/xdpStatistics.ts'

function history(points: XdpHistory['points']): XdpHistory {
  return { period: 'hour', from: '2026-10-23T10:00:00Z', to: '2026-10-23T11:00:00Z', step_seconds: 10, points }
}
function point(at: number, source = 'run1', first_at = at) {
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
