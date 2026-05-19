import {
  type ConditionBlock,
  type ConditionFieldId,
  CONDITION_FIELDS,
  type TransformFields,
} from './wafRuleFields'

let blockSeq = 0
export function newBlockId() {
  blockSeq += 1
  return `b${blockSeq}`
}

export function parseIPCIDRList(raw: string): string[] {
  return [...new Set(raw.split(/[\s,;\n\r]+/).map((s) => s.trim()).filter(Boolean))]
}

export function blocksToCondition(blocks: ConditionBlock[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const b of blocks) {
    if (!b.field) continue
    switch (b.field) {
      case 'method': {
        const m = b.value.trim()
        if (m) out.method = m
        break
      }
      case 'path_exact':
      case 'path_prefix':
      case 'path_contains':
      case 'path_regex':
      case 'request_uri_contains':
      case 'body_contains': {
        const v = b.value.trim()
        if (v) out[b.field] = v
        break
      }
      case 'header_contains': {
        const k = (b.headerKey || '').trim()
        const v = (b.headerVal || '').trim()
        if (!k || !v) break
        const cur = (out.header_contains as Record<string, string>) || {}
        cur[k] = v
        out.header_contains = cur
        break
      }
      case 'query_equals': {
        const k = (b.queryKey || '').trim()
        const v = b.queryVal ?? ''
        if (!k) break
        const cur = (out.query_equals as Record<string, string>) || {}
        cur[k] = v
        out.query_equals = cur
        break
      }
      case 'client_ip_in':
      case 'client_ip_not_in': {
        const ips = parseIPCIDRList(b.value)
        if (ips.length) out[b.field] = ips
        break
      }
    }
  }
  return out
}

export function conditionToBlocks(cond: Record<string, unknown>): ConditionBlock[] {
  const blocks: ConditionBlock[] = []
  const push = (field: ConditionFieldId, partial: Partial<ConditionBlock>) => {
    blocks.push({ id: newBlockId(), field, value: '', ...partial })
  }

  if (cond.method) push('method', { value: String(cond.method) })
  if (cond.path_exact) push('path_exact', { value: String(cond.path_exact) })
  if (cond.path_prefix) push('path_prefix', { value: String(cond.path_prefix) })
  if (cond.path_contains) push('path_contains', { value: String(cond.path_contains) })
  if (cond.path_regex) push('path_regex', { value: String(cond.path_regex) })
  if (cond.request_uri_contains) push('request_uri_contains', { value: String(cond.request_uri_contains) })
  if (cond.body_contains) push('body_contains', { value: String(cond.body_contains) })

  const hdr = cond.header_contains as Record<string, string> | undefined
  if (hdr && typeof hdr === 'object') {
    for (const [k, v] of Object.entries(hdr)) {
      push('header_contains', { headerKey: k, headerVal: v })
    }
  }
  const q = cond.query_equals as Record<string, string> | undefined
  if (q && typeof q === 'object') {
    for (const [k, v] of Object.entries(q)) {
      push('query_equals', { queryKey: k, queryVal: v })
    }
  }
  if (Array.isArray(cond.client_ip_in) && cond.client_ip_in.length) {
    push('client_ip_in', { value: (cond.client_ip_in as string[]).join('\n') })
  }
  if (Array.isArray(cond.client_ip_not_in) && cond.client_ip_not_in.length) {
    push('client_ip_not_in', { value: (cond.client_ip_not_in as string[]).join('\n') })
  }
  return blocks
}

export function parseConditionJson(text: string): { blocks: ConditionBlock[]; error?: string } {
  const t = text.trim() || '{}'
  try {
    const o = JSON.parse(t) as Record<string, unknown>
    if (!o || typeof o !== 'object' || Array.isArray(o)) {
      return { blocks: [], error: 'condition_json должен быть объектом' }
    }
    return { blocks: conditionToBlocks(o) }
  } catch (e) {
    return { blocks: [], error: String(e) }
  }
}

export function buildTransform(action: string, tf: TransformFields): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  if (action === 'redirect' && tf.redirect_url.trim()) {
    out.redirect_url = tf.redirect_url.trim()
  }
  if (action === 'replace') {
    if (tf.replace_from) out.replace_from = tf.replace_from
    if (tf.replace_to) out.replace_to = tf.replace_to
  }
  return out
}

export function parseTransformJson(text: string): TransformFields {
  const empty = { redirect_url: '', replace_from: '', replace_to: '' }
  try {
    const o = JSON.parse(text.trim() || '{}') as Record<string, unknown>
    return {
      redirect_url: String(o.redirect_url ?? ''),
      replace_from: String(o.replace_from ?? ''),
      replace_to: String(o.replace_to ?? ''),
    }
  } catch {
    return empty
  }
}

export function humanSummary(blocks: ConditionBlock[]): string {
  if (!blocks.length) return 'Пустое условие — правило сработает на каждый запрос (все проверки пройдены).'
  const parts = blocks.map((b) => {
    const meta = CONDITION_FIELDS.find((f) => f.id === b.field)
    const label = meta?.label || b.field
    switch (b.field) {
      case 'header_contains':
        return `${label}: ${b.headerKey} ∋ «${b.headerVal}»`
      case 'query_equals':
        return `${label}: ${b.queryKey} = «${b.queryVal}»`
      case 'client_ip_in':
      case 'client_ip_not_in':
        return `${label}: ${parseIPCIDRList(b.value).join(', ') || '—'}`
      default:
        return `${label}: «${b.value || '—'}»`
    }
  })
  return 'Срабатывает, когда одновременно: ' + parts.join(' И ')
}

export function fieldMeta(id: ConditionFieldId) {
  return CONDITION_FIELDS.find((f) => f.id === id)
}
