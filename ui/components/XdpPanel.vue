<template>
  <section class="space-y-5">
    <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 class="text-sm font-semibold text-white">XDP — защита перед WAF</h3>
          <p class="mt-1 text-xs text-slate-400">Фильтрация пакетов на выбранном сетевом интерфейсе до обработки TCP, TLS и HTTP.</p>
        </div>
        <button type="button" class="rounded-lg bg-slate-700 px-3 py-2 text-sm" :disabled="busy" @click="load">Обновить</button>
      </div>
      <p v-if="error" role="alert" class="mt-4 rounded-lg bg-rose-950/60 p-3 text-sm text-rose-200">{{ error }}</p>
      <p v-if="message" role="status" class="mt-4 rounded-lg bg-emerald-950/60 p-3 text-sm text-emerald-200">{{ message }}</p>
      <div v-if="status" class="mt-4 grid gap-3 text-sm sm:grid-cols-3">
        <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Программа</p><p class="mt-1">{{ status.service.ActiveState }} / {{ status.service.SubState }}</p></div>
        <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Интерфейс</p><p class="mt-1 font-mono">{{ status.interface || 'Не выбран' }}</p></div>
        <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Фильтр на интерфейсе</p><p class="mt-1" :class="isAttached ? 'text-emerald-300' : 'text-slate-300'">{{ isAttached ? `Привязан · ID ${programID}` : 'Не привязан' }}</p></div>
      </div>
      <p v-if="status?.attachment_error || status?.config_error" class="mt-3 text-sm text-amber-300">{{ status.attachment_error || status.config_error }}</p>
      <p v-if="isAttached && !running" class="mt-3 text-sm text-amber-300">На интерфейсе уже есть XDP-программа. Запуск FESS не заменит существующий фильтр.</p>
      <div class="mt-4 flex flex-wrap gap-3">
        <button type="button" class="rounded-lg bg-slate-700 px-4 py-2 text-sm disabled:opacity-40" :disabled="busy || !available || running" @click="saveOnly">Сохранить</button>
        <button type="button" class="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-40" :disabled="busy || !available || running || isAttached || !cfg.interface" @click="start">Сохранить и запустить с привязкой</button>
        <button type="button" class="rounded-lg bg-rose-800 px-4 py-2 text-sm text-white disabled:opacity-40" :disabled="busy || !available || !running" @click="stop">Остановить и снять фильтр</button>
      </div>
      <p class="mt-3 text-xs text-slate-400">{{ running ? 'Чтобы изменить интерфейс или параметры, сначала остановите XDP. Во время остановки пакеты обрабатывает обычный сетевой стек.' : 'Сохранение параметров не запускает фильтр. Запуск привяжет программу к выбранному интерфейсу.' }}</p>
    </div>

    <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h4 class="text-sm font-semibold">Статистика XDP</h4>
        <span v-if="statistics" class="text-xs text-slate-400">Снимок {{ new Date(statistics.sampled_at).toLocaleTimeString() }} · обновление каждые 10 с</span>
      </div>
      <p v-if="!statistics" class="mt-3 text-sm text-slate-400">{{ running ? 'Ожидаются данные счётчиков XDP.' : 'Запустите XDP, чтобы получать статистику.' }}</p>
      <template v-else>
        <p v-if="statistics.stale" role="alert" class="mt-3 text-sm text-amber-300">Данные устарели. Скорости не отображаются до получения свежего снимка.</p>
        <p class="mt-2 text-xs text-slate-400">Итоги с запуска {{ new Date(statistics.started_at).toLocaleString() }}. При перезапуске счётчики обнуляются. Весь входящий трафик интерфейса включает другие сервисы.</p>
        <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Всего пакетов</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(statistics.counters.seen) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Пропущено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(statistics.counters.passed) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Отброшено</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ number(totalDropped) }} <span class="text-xs text-slate-400">{{ dropPercent }}%</span></p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('seen') }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Весь интерфейс · Мбит/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('frame_bytes', 8 / 1000000, 2) }}</p></div>
          <div class="rounded-lg bg-slate-800/70 p-3"><p class="text-xs text-slate-400">Защищаемые порты · пакетов/с</p><p class="mt-1 text-xl font-semibold tabular-nums">{{ rate('protected_packets') }}</p></div>
        </div>
        <div class="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <p>Защищаемые порты: <strong>{{ rate('protected_bytes', 8 / 1000000, 2) }}</strong> Мбит/с</p>
          <p>Новые SYN: <strong>{{ rate('protected_syn', 1, 1) }}</strong>/с</p>
          <p>Echo Request: <strong>{{ rate('icmp_echo', 1, 1) }}</strong>/с</p>
        </div>
        <h5 class="mt-5 text-xs font-semibold text-slate-400">Причины отбрасывания</h5>
        <div class="mt-3 grid gap-2 sm:grid-cols-2">
          <div v-for="reason in dropReasons" :key="reason.key" class="flex justify-between gap-3 rounded-lg bg-slate-800/50 px-3 py-2 text-xs"><span>{{ reason.label }}</span><span class="font-mono tabular-nums">{{ number(statistics.counters[reason.key]) }}</span></div>
        </div>
        <p class="mt-3 text-xs text-slate-400">Неразобранные пакеты, переданные сетевому стеку: {{ number(statistics.counters.malformed_pass) }}. Скорости рассчитаны по разнице двух снимков, это не HTTP RPS.</p>
      </template>
    </div>

    <fieldset :disabled="busy || !available || running" class="space-y-5 disabled:opacity-60">
      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <h4 class="text-sm font-semibold">Интерфейс и область защиты</h4>
        <div class="mt-4 grid gap-4 sm:grid-cols-2">
          <label class="text-xs text-slate-400">Сетевой интерфейс
            <select v-model="cfg.interface" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white"><option value="">Выберите интерфейс</option><option v-for="iface in interfaces" :key="iface.name" :value="iface.name">{{ iface.name }} · {{ iface.up ? 'UP' : 'DOWN' }} · {{ iface.addresses.join(', ') || 'без IP' }}</option></select>
          </label>
          <label class="text-xs text-slate-400">Режим привязки
            <select v-model="cfg.mode" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white"><option value="native">Native — в драйвере</option><option value="generic">Generic — в сетевом стеке</option></select>
          </label>
          <label class="text-xs text-slate-400">Защищаемые порты, по одному на строку
            <textarea v-model="ports" rows="3" placeholder="tcp/80&#10;tcp/443" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 font-mono text-sm text-white" />
          </label>
          <div class="space-y-3">
            <label class="block text-xs text-slate-400">Пакетов/с на IP · 0 — без лимита<input v-model.number="cfg.packets_per_second" type="number" min="0" max="1000000000" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-white" /></label>
            <label class="block text-xs text-slate-400">SYN/с на IP · 0 — без лимита<input v-model.number="cfg.syns_per_second" type="number" min="0" max="1000000000" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-white" /></label>
          </div>
          <label class="text-xs text-slate-400">Запрещённые CIDR<textarea v-model="blockedCIDRs" rows="3" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 font-mono text-sm text-white" /></label>
          <label class="text-xs text-slate-400">Разрешённые CIDR · обходят лимиты и баны<textarea v-model="allowedCIDRs" rows="3" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 font-mono text-sm text-white" /></label>
        </div>
        <label class="mt-4 flex items-center gap-2 text-sm"><input v-model="cfg.drop_fragments" type="checkbox" />Отбрасывать IP-фрагменты на всём интерфейсе</label>
      </div>

      <div v-for="section in budgets" :key="section.key" class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <label class="flex items-center gap-2 text-sm font-semibold"><input v-model="cfg[section.key].enabled" type="checkbox" />{{ section.title }}</label>
        <p class="mt-2 text-xs text-slate-400">{{ section.hint }}</p>
        <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <label v-for="field in section.fields" :key="field.key" class="text-xs text-slate-400">{{ field.label }}
            <input v-model.number="cfg[section.key][field.key]" type="number" min="0" max="1000000000" :disabled="!cfg[section.key].enabled" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white disabled:opacity-40" />
          </label>
        </div>
      </div>

      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <label class="flex items-center gap-2 text-sm font-semibold"><input v-model="cfg.malformed_packets.enabled" type="checkbox" />Проверка некорректных пакетов</label>
        <p class="mt-2 text-xs text-slate-400">Проверки применяются к выбранным TCP/UDP-портам. Заголовки, по которым нельзя определить порт, остаются сетевому стеку.</p>
        <label class="mt-4 flex items-center gap-2 text-sm"><input v-model="cfg.malformed_packets.invalid_lengths" type="checkbox" :disabled="!cfg.malformed_packets.enabled" />Длины IP/TCP/UDP и размер TCP-заголовка</label>
        <label class="mt-3 flex items-center gap-2 text-sm"><input v-model="cfg.malformed_packets.invalid_tcp_flags" type="checkbox" :disabled="!cfg.malformed_packets.enabled" />Недопустимые флаги SYN+FIN и SYN+RST</label>
      </div>

      <div class="rounded-2xl border border-white/10 bg-slate-900/50 p-6">
        <label class="flex items-center gap-2 text-sm font-semibold"><input v-model="cfg.temporary_blocks.enabled" type="checkbox" />Временные блокировки из WAF</label>
        <p class="mt-2 text-xs text-slate-400">После блокировки правилом WAF прямой клиент временно блокируется на всех защищаемых портах. Доверенные прокси исключаются. За общим NAT блокировка может затронуть нескольких клиентов.</p>
        <div class="mt-4 grid gap-3 sm:grid-cols-3">
          <label class="text-xs text-slate-400">Срабатываний WAF до бана<input v-model.number="cfg.temporary_blocks.min_events" type="number" min="1" max="1000000" :disabled="!cfg.temporary_blocks.enabled" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white" /></label>
          <label class="text-xs text-slate-400">Окно срабатываний, секунд<input v-model.number="cfg.temporary_blocks.window_seconds" type="number" min="1" max="86400" :disabled="!cfg.temporary_blocks.enabled" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white" /></label>
        <label class="block text-xs text-slate-400">Срок блокировки, секунд<input v-model.number="cfg.temporary_blocks.ttl_seconds" type="number" min="1" max="86400" :disabled="!cfg.temporary_blocks.enabled" class="mt-1 w-full rounded-lg border border-slate-600 bg-slate-950 p-2 text-sm text-white" /></label>
        </div>
      </div>
    </fieldset>
  </section>
</template>

<script setup lang="ts">
const { apiUrl, apiFetch } = useApi()
type Budget = { enabled: boolean; [key: string]: number | boolean }
type Statistics = { pid: number; started_at: string; sampled_at: string; interval_seconds: number; stale: boolean; counters: Record<string, number>; rates: Record<string, number> }
type Status = { service: Record<string, string>; interface: string; mode: string; attachment: { prog?: { id?: number }; prog_id?: number } | null; attachment_error?: string; config_error?: string; statistics?: Statistics | null; statistics_error?: string }
const cfg = ref({
  interface: '', mode: 'native', ports: [] as { protocol: string; port: number }[], block_cidrs: [] as string[], allow_cidrs: [] as string[],
  packets_per_second: 10000, syns_per_second: 1000, drop_fragments: false,
  global_budget: { enabled: false, packets_per_second: 100000, packet_burst: 200000, bytes_per_second: 100000000, byte_burst: 200000000, syns_per_second: 10000, syn_burst: 20000 } as Budget,
  icmp_ping: { enabled: false, packets_per_second: 1000, burst: 2000, per_ip_packets_per_second: 10, per_ip_burst: 20 } as Budget,
  malformed_packets: { enabled: false, invalid_lengths: true, invalid_tcp_flags: true },
  temporary_blocks: { enabled: false, socket_path: '/run/fess-xdp/blocks.sock', socket_group: 'fess', ttl_seconds: 60, min_events: 3, window_seconds: 30 },
})
const budgets: { key: 'global_budget' | 'icmp_ping'; title: string; hint: string; fields: { key: string; label: string }[] }[] = [
  { key: 'global_budget', title: 'Общие бюджеты', hint: 'Общий лимит для всех выбранных TCP/UDP-портов и источников. Burst — допустимый всплеск; пара нулей выключает измерение.', fields: [
    { key: 'packets_per_second', label: 'Пакетов/с' }, { key: 'packet_burst', label: 'Burst, пакетов' }, { key: 'bytes_per_second', label: 'Байт/с' }, { key: 'byte_burst', label: 'Burst, байт' }, { key: 'syns_per_second', label: 'SYN/с' }, { key: 'syn_burst', label: 'Burst, SYN' },
  ] },
  { key: 'icmp_ping', title: 'Защита от ICMP Ping Flood', hint: 'Только Echo Request IPv4/IPv6 на всём интерфейсе. Служебный ICMP, Packet Too Big и NDP сохраняются.', fields: [
    { key: 'packets_per_second', label: 'Всего пакетов/с' }, { key: 'burst', label: 'Общий burst' }, { key: 'per_ip_packets_per_second', label: 'Пакетов/с на IP' }, { key: 'per_ip_burst', label: 'Burst на IP' },
  ] },
]
const ports = ref('tcp/80\ntcp/443'), blockedCIDRs = ref(''), allowedCIDRs = ref('')
const interfaces = ref<{ name: string; up: boolean; addresses: string[] }[]>([])
const status = ref<Status | null>(null)
const available = ref(false), busy = ref(false), error = ref(''), message = ref('')
const running = computed(() => !!status.value && !['inactive', 'failed'].includes(status.value.service.ActiveState || ''))
const programID = computed(() => status.value?.attachment?.prog?.id || status.value?.attachment?.prog_id || 0)
const isAttached = computed(() => programID.value > 0)
const statistics = computed(() => status.value?.statistics || null)
const dropReasons = [
  { key: 'cidr_drop', label: 'CIDR deny' }, { key: 'rate_drop', label: 'Лимит на IP' },
  { key: 'global_budget_drop', label: 'Общий бюджет' }, { key: 'icmp_ping_drop', label: 'ICMP Ping Flood' },
  { key: 'malformed_drop', label: 'Некорректные пакеты' }, { key: 'temporary_block_drop', label: 'Временные баны WAF' },
  { key: 'fragment_drop', label: 'IP-фрагменты' },
]
const totalDropped = computed(() => dropReasons.reduce((sum, r) => sum + (statistics.value?.counters[r.key] || 0), 0))
const dropPercent = computed(() => statistics.value?.counters.seen ? (100 * totalDropped.value / statistics.value.counters.seen).toFixed(2) : '0.00')
function number(value: number | undefined, digits = 0) { return (value || 0).toLocaleString(undefined, { maximumFractionDigits: digits }) }
function rate(key: string, scale = 1, digits = 0) {
  const stats = statistics.value
  return stats && !stats.stale && stats.interval_seconds > 0 && typeof stats.rates[key] === 'number' ? number(stats.rates[key]! * scale, digits) : '—'
}

function errorMessage(e: any) { return e?.data?.error || e?.message || 'Не удалось выполнить действие XDP' }
async function refreshStatus() { status.value = await apiFetch<Status>(apiUrl('/settings/xdp/status')) }
async function load() {
  busy.value = true; error.value = ''; message.value = ''
  try {
    const [settings, ifaces] = await Promise.all([apiFetch<{ config: typeof cfg.value }>(apiUrl('/settings/xdp')), apiFetch<{ items: typeof interfaces.value }>(apiUrl('/settings/xdp/interfaces'))])
    cfg.value = settings.config
    if (!cfg.value.temporary_blocks.socket_path) cfg.value.temporary_blocks.socket_path = '/run/fess-xdp/blocks.sock'
    if (!cfg.value.temporary_blocks.socket_group) cfg.value.temporary_blocks.socket_group = 'fess'
    if (!cfg.value.temporary_blocks.ttl_seconds) cfg.value.temporary_blocks.ttl_seconds = 60
    if (!cfg.value.temporary_blocks.min_events) cfg.value.temporary_blocks.min_events = 1
    if (!cfg.value.temporary_blocks.window_seconds) cfg.value.temporary_blocks.window_seconds = 60
    interfaces.value = ifaces.items
    ports.value = (cfg.value.ports || []).map(p => `${p.protocol}/${p.port}`).join('\n')
    blockedCIDRs.value = (cfg.value.block_cidrs || []).join('\n'); allowedCIDRs.value = (cfg.value.allow_cidrs || []).join('\n')
    await refreshStatus(); available.value = true
  } catch (e) { error.value = errorMessage(e); available.value = false }
  finally { busy.value = false }
}
function lines(value: string) { return value.split(/[\s,]+/).filter(Boolean) }
async function save() {
  const parsed = lines(ports.value).map(value => {
    const match = /^(tcp|udp)\/(\d+)$/.exec(value)
    if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) throw new Error(`Некорректный порт: ${value}. Используйте tcp/80 или udp/443.`)
    return { protocol: match[1]!, port: Number(match[2]) }
  })
  if (!parsed.length) throw new Error('Укажите хотя бы один защищаемый порт')
  cfg.value.ports = parsed; cfg.value.block_cidrs = lines(blockedCIDRs.value); cfg.value.allow_cidrs = lines(allowedCIDRs.value)
  await apiFetch(apiUrl('/settings/xdp'), { method: 'PUT', body: { config: cfg.value } })
}
async function action(work: () => Promise<void>) {
  busy.value = true; error.value = ''; message.value = ''
  try { await work() } catch (e) { error.value = errorMessage(e) }
  finally { try { await refreshStatus() } catch {} busy.value = false }
}
function saveOnly() { return action(async () => { await save(); message.value = 'Параметры сохранены. Фильтр остановлен.' }) }
function start() { return action(async () => { await save(); await apiFetch(apiUrl('/settings/xdp/start'), { method: 'POST' }); message.value = 'XDP запущен и привязан к выбранному интерфейсу.' }) }
function stop() { return action(async () => { await apiFetch(apiUrl('/settings/xdp/stop'), { method: 'POST' }); message.value = 'XDP остановлен. Его фильтр снят с интерфейса.' }) }
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { load(); timer = setInterval(() => { if (available.value && !busy.value) refreshStatus().catch(() => { available.value = false; error.value = 'Связь с контроллером XDP потеряна. Обновите статус.' }) }, 5000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>
