<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="max-w-2xl">
        <h2 class="text-lg font-semibold text-white">Конструктор правил WAF</h2>
        <p class="mt-1 text-sm text-slate-400">
          Соберите <code class="rounded bg-slate-800 px-1 text-xs">condition_json</code> из блоков. Все блоки объединяются через
          <strong class="text-slate-300">И</strong> (логическое AND). Приоритет правила: меньшее число — раньше в цепочке.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          @click="showReference = !showReference"
        >
          {{ showReference ? 'Скрыть справочник' : 'Справочник переменных' }}
        </button>
        <button
          type="button"
          class="rounded-lg border border-teal-700/60 bg-teal-900/30 px-3 py-1.5 text-sm text-teal-200 hover:bg-teal-900/50"
          @click="addBlock()"
        >
          + Условие
        </button>
      </div>
    </div>

    <div v-if="showReference" class="grid gap-4 lg:grid-cols-2">
      <section class="rounded-xl border border-slate-700/80 bg-slate-950/80 p-4">
        <h3 class="text-sm font-medium text-teal-300">Поля condition_json</h3>
        <ul class="mt-3 max-h-96 space-y-3 overflow-y-auto pr-1 text-xs">
          <li v-for="f in CONDITION_FIELDS" :key="f.id" class="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div class="font-mono text-teal-200">{{ f.jsonKey }}</div>
            <div class="mt-0.5 font-medium text-slate-200">{{ f.label }}</div>
            <p class="mt-1 text-slate-400">{{ f.description }}</p>
            <pre class="mt-2 overflow-x-auto rounded bg-slate-950 p-2 text-[10px] text-slate-500">{{ f.example }}</pre>
          </li>
        </ul>
      </section>
      <section class="space-y-4">
        <div class="rounded-xl border border-slate-700/80 bg-slate-950/80 p-4">
          <h3 class="text-sm font-medium text-violet-300">Действия (action)</h3>
          <ul class="mt-2 space-y-1 text-xs text-slate-400">
            <li v-for="a in WAF_ACTIONS" :key="a.id">
              <span class="font-mono text-slate-200">{{ a.id }}</span> — {{ a.label }}
            </li>
          </ul>
        </div>
        <div class="rounded-xl border border-slate-700/80 bg-slate-950/80 p-4">
          <h3 class="text-sm font-medium text-amber-300">transform_json</h3>
          <ul class="mt-2 space-y-2 text-xs">
            <li v-for="t in TRANSFORM_FIELDS" :key="t.id" class="text-slate-400">
              <span class="font-mono text-amber-200/90">{{ t.label }}</span> — {{ t.description }}
              <pre class="mt-1 rounded bg-slate-950 p-2 text-[10px] text-slate-500">{{ t.example }}</pre>
            </li>
          </ul>
        </div>
        <div class="rounded-xl border border-slate-700/80 bg-slate-950/80 p-4">
          <h3 class="text-sm font-medium text-slate-300">Контекст запроса</h3>
          <ul class="mt-2 space-y-2 text-xs text-slate-400">
            <li v-for="v in RUNTIME_VARIABLES" :key="v.name">
              <span class="font-mono text-slate-200">{{ v.name }}</span> — {{ v.description }}
            </li>
          </ul>
        </div>
      </section>
    </div>

    <section class="rounded-xl border border-white/10 bg-slate-900/40 p-4">
      <h3 class="text-sm font-medium text-slate-300">Параметры правила</h3>
      <div class="mt-3 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
        <div class="lg:col-span-2">
          <label class="text-xs text-slate-500">Имя правила</label>
          <input
            v-model="ruleName"
            class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            placeholder="block-admin-from-internet"
          />
        </div>
        <div>
          <label class="text-xs text-slate-500">Действие</label>
          <select v-model="ruleAction" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
            <option v-for="a in WAF_ACTIONS" :key="a.id" :value="a.id">{{ a.label }}</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-slate-500">Приоритет</label>
          <input v-model.number="rulePriority" type="number" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
        </div>
      </div>

      <div v-if="ruleAction === 'redirect' || ruleAction === 'replace'" class="mt-4 grid gap-3 md:grid-cols-2">
        <template v-if="ruleAction === 'redirect'">
          <div class="md:col-span-2">
            <label class="text-xs text-slate-500">redirect_url</label>
            <input
              v-model="transform.redirect_url"
              class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm"
              placeholder="https://example.com/blocked"
            />
          </div>
        </template>
        <template v-if="ruleAction === 'replace'">
          <div>
            <label class="text-xs text-slate-500">replace_from</label>
            <input v-model="transform.replace_from" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm" />
          </div>
          <div>
            <label class="text-xs text-slate-500">replace_to</label>
            <input v-model="transform.replace_to" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm" />
          </div>
        </template>
      </div>
    </section>

    <section class="space-y-3">
      <p v-if="!blocks.length" class="rounded-lg border border-dashed border-slate-700 px-4 py-6 text-center text-sm text-slate-500">
        Нет условий — добавьте блок или загрузите из существующего правила.
      </p>

      <div
        v-for="(block, idx) in blocks"
        :key="block.id"
        class="rounded-xl border border-slate-700/80 bg-slate-950/60 p-4"
      >
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="text-xs font-medium text-slate-500">Условие {{ idx + 1 }}</span>
          <button type="button" class="text-xs text-red-400 hover:text-red-300" @click="removeBlock(block.id)">Удалить</button>
        </div>
        <div class="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <label class="text-xs text-slate-500">Тип проверки</label>
            <select
              v-model="block.field"
              class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
              @change="onFieldChange(block)"
            >
              <option v-for="f in CONDITION_FIELDS" :key="f.id" :value="f.id">{{ f.label }} ({{ f.jsonKey }})</option>
            </select>
            <p v-if="fieldMeta(block.field)" class="mt-2 text-xs text-slate-500">{{ fieldMeta(block.field)?.description }}</p>
          </div>

          <template v-if="block.field === 'method'">
            <div>
              <label class="text-xs text-slate-500">Метод</label>
              <select v-model="block.value" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm">
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
                <option>HEAD</option>
                <option>OPTIONS</option>
              </select>
            </div>
          </template>

          <template v-else-if="block.field === 'header_contains'">
            <div>
              <label class="text-xs text-slate-500">Имя заголовка</label>
              <input v-model="block.headerKey" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" placeholder="User-Agent" />
            </div>
            <div>
              <label class="text-xs text-slate-500">Подстрока в значении</label>
              <input v-model="block.headerVal" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" placeholder="curl" />
            </div>
          </template>

          <template v-else-if="block.field === 'query_equals'">
            <div>
              <label class="text-xs text-slate-500">Имя параметра</label>
              <input v-model="block.queryKey" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" placeholder="debug" />
            </div>
            <div>
              <label class="text-xs text-slate-500">Значение</label>
              <input v-model="block.queryVal" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" placeholder="1" />
            </div>
          </template>

          <template v-else-if="block.field === 'client_ip_in' || block.field === 'client_ip_not_in'">
            <div class="md:col-span-2">
              <label class="text-xs text-slate-500">IP или CIDR (по одному в строке)</label>
              <textarea
                v-model="block.value"
                rows="4"
                class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs"
                :placeholder="fieldMeta(block.field)?.placeholder"
              />
            </div>
          </template>

          <template v-else>
            <div class="md:col-span-2">
              <label class="text-xs text-slate-500">{{ fieldMeta(block.field)?.valueLabel || 'Значение' }}</label>
              <input
                v-model="block.value"
                class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm"
                :placeholder="fieldMeta(block.field)?.placeholder"
              />
            </div>
          </template>
        </div>
        <p v-if="idx < blocks.length - 1" class="mt-3 text-center text-xs font-medium text-teal-600/80">И</p>
      </div>
    </section>

    <section class="rounded-xl border border-slate-800 bg-slate-950/80 p-4">
      <h3 class="text-sm font-medium text-slate-300">Предпросмотр</h3>
      <p class="mt-2 text-sm text-slate-400">{{ summary }}</p>
      <div class="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div class="text-xs text-slate-500">condition_json</div>
          <pre class="mt-1 max-h-48 overflow-auto rounded-lg border border-slate-800 bg-black/40 p-3 font-mono text-xs text-emerald-200/90">{{ conditionPreview }}</pre>
        </div>
        <div>
          <div class="text-xs text-slate-500">transform_json</div>
          <pre class="mt-1 max-h-48 overflow-auto rounded-lg border border-slate-800 bg-black/40 p-3 font-mono text-xs text-amber-200/90">{{ transformPreview }}</pre>
        </div>
      </div>
      <p v-if="jsonError" class="mt-2 text-sm text-red-400">{{ jsonError }}</p>
    </section>

    <div class="flex flex-wrap gap-2">
      <button
        type="button"
        class="rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
        :disabled="disabled || !policyId"
        @click="emitSave('create')"
      >
        Создать правило в политике
      </button>
      <button
        type="button"
        class="rounded-lg bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-600 disabled:opacity-50"
        :disabled="disabled || !policyId"
        @click="emitApply"
      >
        Применить к форме ниже
      </button>
      <button
        v-if="editingRuleId"
        type="button"
        class="rounded-lg bg-violet-700 px-4 py-2 text-sm text-white hover:bg-violet-600 disabled:opacity-50"
        :disabled="disabled || !policyId"
        @click="emitSave('update')"
      >
        Сохранить правило #{{ editingRuleId.slice(0, 8) }}…
      </button>
      <button type="button" class="rounded-lg border border-slate-600 px-4 py-2 text-sm hover:bg-slate-800" @click="copyJson">
        Копировать JSON
      </button>
      <button type="button" class="rounded-lg border border-slate-600 px-4 py-2 text-sm hover:bg-slate-800" @click="resetBuilder">
        Сбросить
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  CONDITION_FIELDS,
  RUNTIME_VARIABLES,
  TRANSFORM_FIELDS,
  WAF_ACTIONS,
  type ConditionBlock,
  type ConditionFieldId,
} from '~/composables/wafRuleFields'
import {
  blocksToCondition,
  buildTransform,
  fieldMeta,
  humanSummary,
  newBlockId,
  parseConditionJson,
  parseTransformJson,
} from '~/composables/useWafRuleBuilder'

const props = defineProps<{
  policyId: string | null
  disabled?: boolean
}>()

const emit = defineEmits<{
  apply: [payload: { name: string; action: string; priority: number; conditionText: string; transformText: string }]
  save: [payload: { mode: 'create' | 'update'; ruleId?: string; name: string; action: string; priority: number; conditionText: string; transformText: string }]
}>()

const showReference = ref(true)
const ruleName = ref('')
const ruleAction = ref('block')
const rulePriority = ref(100)
const transform = reactive({ redirect_url: '', replace_from: '', replace_to: '' })
const blocks = ref<ConditionBlock[]>([])
const editingRuleId = ref<string | null>(null)
const jsonError = ref('')

const conditionObj = computed(() => blocksToCondition(blocks.value))
const conditionPreview = computed(() => JSON.stringify(conditionObj.value, null, 2))
const transformPreview = computed(() => JSON.stringify(buildTransform(ruleAction.value, transform), null, 2))
const summary = computed(() => humanSummary(blocks.value))

function addBlock(field: ConditionFieldId = 'path_contains') {
  const b: ConditionBlock = { id: newBlockId(), field, value: '' }
  if (field === 'method') b.value = 'GET'
  if (field === 'header_contains') {
    b.headerKey = 'User-Agent'
    b.headerVal = ''
  }
  blocks.value.push(b)
}

function removeBlock(id: string) {
  blocks.value = blocks.value.filter((b) => b.id !== id)
}

function onFieldChange(block: ConditionBlock) {
  block.value = ''
  if (block.field === 'method') block.value = 'GET'
}

function resetBuilder() {
  blocks.value = []
  ruleName.value = ''
  ruleAction.value = 'block'
  rulePriority.value = 100
  transform.redirect_url = ''
  transform.replace_from = ''
  transform.replace_to = ''
  editingRuleId.value = null
  jsonError.value = ''
  addBlock('path_contains')
}

function loadFromRule(row: { id: string; name: string; action: string; priority: number; conditionText: string; transformText: string }) {
  editingRuleId.value = row.id
  ruleName.value = row.name
  ruleAction.value = row.action
  rulePriority.value = row.priority
  const parsed = parseConditionJson(row.conditionText)
  blocks.value = parsed.blocks.length ? parsed.blocks : [{ id: newBlockId(), field: 'path_contains', value: '' }]
  jsonError.value = parsed.error || ''
  const tf = parseTransformJson(row.transformText)
  transform.redirect_url = tf.redirect_url
  transform.replace_from = tf.replace_from
  transform.replace_to = tf.replace_to
}

function emitApply() {
  emit('apply', payload())
}

function emitSave(mode: 'create' | 'update') {
  if (!ruleName.value.trim()) {
    jsonError.value = 'Укажите имя правила'
    return
  }
  jsonError.value = ''
  emit('save', {
    mode,
    ruleId: editingRuleId.value || undefined,
    ...payload(),
  })
}

function payload() {
  return {
    name: ruleName.value.trim(),
    action: ruleAction.value,
    priority: rulePriority.value,
    conditionText: conditionPreview.value,
    transformText: transformPreview.value,
  }
}

async function copyJson() {
  const text = `condition:\n${conditionPreview.value}\n\ntransform:\n${transformPreview.value}`
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    /* ignore */
  }
}

defineExpose({ loadFromRule, resetBuilder, addBlock })

if (blocks.value.length === 0) {
  addBlock('path_contains')
}
</script>
