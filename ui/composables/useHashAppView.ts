export type HashAppView = 'main' | 'waf-events' | 'waf-event'

export type WafEventsHashParams = {
  hours?: number
  rule_id?: string
  action?: string
}

function parseHash(): { view: HashAppView; eventId: number | null; eventsParams: WafEventsHashParams } {
  if (!import.meta.client) {
    return { view: 'main', eventId: null, eventsParams: {} }
  }
  const raw = (window.location.hash || '').replace(/^#/, '').trim()
  if (!raw) {
    return { view: 'main', eventId: null, eventsParams: {} }
  }
  if (raw.startsWith('waf-event/')) {
    const id = parseInt(raw.slice('waf-event/'.length), 10)
    if (id > 0) {
      return { view: 'waf-event', eventId: id, eventsParams: {} }
    }
    return { view: 'main', eventId: null, eventsParams: {} }
  }
  if (raw.startsWith('waf-events')) {
    const q = raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : ''
    const sp = new URLSearchParams(q)
    const params: WafEventsHashParams = {}
    const h = sp.get('hours')
    if (h) {
      const n = parseInt(h, 10)
      if (!Number.isNaN(n) && n > 0) params.hours = n
    }
    const rid = sp.get('rule_id')
    if (rid) params.rule_id = rid
    const act = sp.get('action')
    if (act) params.action = act
    return { view: 'waf-events', eventId: null, eventsParams: params }
  }
  return { view: 'main', eventId: null, eventsParams: {} }
}

export function useHashAppView() {
  const view = ref<HashAppView>('main')
  const eventId = ref<number | null>(null)
  const eventsParams = ref<WafEventsHashParams>({})

  function syncFromHash() {
    const p = parseHash()
    view.value = p.view
    eventId.value = p.eventId
    eventsParams.value = p.eventsParams
  }

  function setHash(fragment: string) {
    if (!import.meta.client) return
    const next = fragment ? `#${fragment}` : ''
    if (window.location.hash !== next) {
      window.location.hash = next
    }
    syncFromHash()
  }

  function openWafEventsExplorer(params: WafEventsHashParams = {}) {
    const sp = new URLSearchParams()
    if (params.hours) sp.set('hours', String(params.hours))
    if (params.rule_id) sp.set('rule_id', params.rule_id)
    if (params.action) sp.set('action', params.action)
    const q = sp.toString()
    setHash(q ? `waf-events?${q}` : 'waf-events')
  }

  function openWafEventDetail(id: number, returnParams?: WafEventsHashParams) {
    if (returnParams && (returnParams.hours || returnParams.rule_id || returnParams.action)) {
      try {
        sessionStorage.setItem('fence_waf_events_return', JSON.stringify(returnParams))
      } catch {
        /* ignore */
      }
    }
    setHash(`waf-event/${id}`)
  }

  function closeOverlay() {
    setHash('')
  }

  function backFromEventDetail() {
    try {
      const raw = sessionStorage.getItem('fence_waf_events_return')
      sessionStorage.removeItem('fence_waf_events_return')
      if (raw) {
        const p = JSON.parse(raw) as WafEventsHashParams
        openWafEventsExplorer(p)
        return
      }
    } catch {
      /* ignore */
    }
    setHash('waf-events')
  }

  onMounted(() => {
    syncFromHash()
    window.addEventListener('hashchange', syncFromHash)
  })

  onBeforeUnmount(() => {
    if (import.meta.client) {
      window.removeEventListener('hashchange', syncFromHash)
    }
  })

  return {
    view,
    eventId,
    eventsParams,
    openWafEventsExplorer,
    openWafEventDetail,
    closeOverlay,
    backFromEventDetail,
    syncFromHash,
  }
}
