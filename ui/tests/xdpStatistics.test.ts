import assert from 'node:assert/strict'
import test from 'node:test'
import { appendXdpSample, xdpDropped } from '../utils/xdpStatistics.ts'
import type { XdpHistory, XdpStatistics } from '../utils/xdpStatistics.ts'

const empty = (): XdpHistory => ({ source: '', points: [] })
function sample(seconds = 10, changes: Partial<XdpStatistics> = {}): XdpStatistics {
  return { pid: 42, program_id: 100, interface: 'ens3', started_at: '2026-10-23T10:00:00Z', sampled_at: new Date(Date.parse('2026-10-23T10:00:00Z') + seconds * 1000).toISOString(), interval_seconds: 10, stale: false, counters: {}, rates: { seen: 200, passed: 197, global_budget_drop: 1, temporary_block_drop: 2 }, ...changes }
}

test('polls of the same snapshot do not create duplicate chart points', () => {
  let history = appendXdpSample(empty(), sample())
  history = appendXdpSample(history, sample())
  history = appendXdpSample(history, sample(9))
  assert.equal(history.points.length, 1)
  assert.equal(history.points[0]?.rates?.dropped, 3)
})

test('unavailable, stale and initial rate samples never become zero traffic', () => {
  let history = appendXdpSample(empty(), sample(0, { interval_seconds: 0, rates: {} }))
  assert.equal(history.points.length, 0)
  history = appendXdpSample(history, sample())
  history = appendXdpSample(history, sample(20, { stale: true }))
  assert.equal(history.points.length, 1)
  history = appendXdpSample(history, sample(30))
  assert.equal(history.points.length, 3)
  assert.equal(history.points[1]?.rates, null)
})

test('program restarts and interface changes reset the series', () => {
  for (const change of [{ pid: 43 }, { program_id: 101 }, { interface: 'eth0' }, { started_at: '2026-10-23T10:00:20Z' }]) {
    const history = appendXdpSample(appendXdpSample(empty(), sample()), sample(30, change))
    assert.equal(history.points.length, 1)
  }
})

test('history is bounded to fifteen minutes and a long outage drops the old series', () => {
  let history = empty()
  for (let seconds = 10; seconds <= 2000; seconds += 10) history = appendXdpSample(history, sample(seconds))
  assert.equal(history.points.length, 91)
  assert.equal(history.points[0]?.at, Date.parse(sample(1100).sampled_at))
  history = appendXdpSample(history, sample(4000))
  assert.equal(history.points.length, 1)
})

test('drop totals exclude traffic and malformed packets passed to the stack', () => {
  assert.equal(xdpDropped({ seen: 999, passed: 900, malformed_pass: 20, protected_packets: 200, icmp_ping_drop: 3, cidr_drop: 2, malformed_drop: 4 }), 9)
})
