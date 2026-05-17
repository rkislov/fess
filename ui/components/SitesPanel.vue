<template>
  <div class="space-y-8">
    <p v-if="err" class="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{{ err }}</p>
    <p v-if="ok" class="rounded-lg border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200">{{ ok }}</p>

    <!-- Список сайтов -->
    <section class="rounded-2xl border border-white/10 bg-slate-900/50 p-6 shadow-lg shadow-black/20 backdrop-blur-sm">
      <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 class="text-lg font-semibold text-white">Список сайтов</h2>
          <p class="mt-1 text-sm text-slate-400">Клик по строке выделяет сайт. «Редактировать» открывает окно с параметрами, TLS и бэкендами.</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            class="rounded-lg bg-gradient-to-r from-teal-600 to-emerald-600 px-4 py-2 text-sm font-medium text-white shadow-md hover:from-teal-500 hover:to-emerald-500"
            :disabled="busy"
            @click="openAddWizard"
          >
            Добавить сайт
          </button>
          <button type="button" class="rounded-lg bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700" :disabled="busy" @click="loadSites">
            Обновить список
          </button>
        </div>
      </div>

      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="border-b border-slate-700 text-slate-500">
              <th class="py-2 pr-3">Название</th>
              <th class="py-2 pr-3">Host</th>
              <th class="py-2 pr-3">Приоритет</th>
              <th class="py-2 pr-3">Вкл.</th>
              <th class="py-2 pr-3">Политика WAF</th>
              <th class="py-2 pr-3">HTTPS</th>
              <th class="py-2 text-right">Действия</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!sites.length && !busy">
              <td colspan="7" class="py-10 text-center text-slate-500">Нет сайтов — нажмите «Добавить сайт».</td>
            </tr>
            <tr
              v-for="s in sites"
              :key="s.id"
              class="cursor-pointer border-b border-slate-800/80 transition hover:bg-slate-800/40"
              :class="selectedId === s.id ? 'bg-sky-950/35' : ''"
              @click="selectSite(s)"
            >
              <td class="py-2.5 pr-3 font-medium text-slate-100">{{ s.name }}</td>
              <td class="py-2.5 pr-3 font-mono text-xs text-slate-300">{{ s.host_pattern }}</td>
              <td class="py-2.5 pr-3 text-slate-400">{{ s.priority }}</td>
              <td class="py-2.5 pr-3">
                <span :class="s.enabled ? 'text-emerald-400' : 'text-slate-500'">{{ s.enabled ? 'да' : 'нет' }}</span>
              </td>
              <td class="max-w-[180px] truncate py-2.5 pr-3 text-xs text-slate-400" :title="policyLabel(s.policy_id)">
                {{ policyLabel(s.policy_id) }}
              </td>
              <td class="py-2.5 pr-3">
                <span v-if="s.tls_enabled && s.tls_has_certificate" class="text-emerald-400" title="TLS настроен">🔒</span>
                <span v-else class="text-slate-600">—</span>
              </td>
              <td class="py-2.5 text-right">
                <button
                  type="button"
                  class="rounded-md border border-slate-600 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:border-teal-500/50 hover:bg-slate-700 hover:text-white"
                  :disabled="busy"
                  @click.stop="openEditModal(s)"
                >
                  Редактировать
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <Teleport to="body">
      <div
        v-if="sitePanelOpen"
        class="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-sm sm:p-8"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="sitePanelMode === 'create' ? 'site-panel-title-create' : 'site-panel-title-edit'"
        @click.self="closeSitePanel"
      >
        <div
          class="relative mt-0 w-full max-w-4xl rounded-2xl border border-white/10 bg-slate-900 shadow-2xl shadow-black/40 sm:mt-8"
        >
          <!-- Создание -->
          <div v-if="sitePanelMode === 'create'" class="p-6 sm:p-8">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 id="site-panel-title-create" class="text-lg font-semibold text-white">Новый сайт — по шагам</h2>
                <p class="mt-1 text-sm text-slate-400">
                  Виртуальный хост, бэкенд и при необходимости TLS (SNI по шаблону хоста).
                </p>
              </div>
              <button
                type="button"
                class="shrink-0 rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
                :disabled="busy"
                @click="closeSitePanel"
              >
                Закрыть
              </button>
            </div>

            <div class="mt-5 flex flex-wrap gap-2" role="navigation" aria-label="Шаги мастера">
              <button
                v-for="(label, idx) in stepLabels"
                :key="idx"
                type="button"
                class="rounded-lg px-3 py-1.5 text-sm font-medium transition"
                :class="
                  wizardStep === idx + 1
                    ? 'bg-teal-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-white'
                "
                @click="goWizardStep(idx + 1)"
              >
                {{ idx + 1 }}. {{ label }}
              </button>
            </div>

            <div class="mt-6 border-t border-slate-800 pt-6">
              <div v-show="wizardStep === 1" class="space-y-3">
                <h3 class="text-sm font-medium text-slate-300">Сайт и политика</h3>
                <input
                  v-model="wizard.name"
                  placeholder="Название (например, API production)"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                />
                <input
                  v-model="wizard.host_pattern"
                  placeholder="Шаблон Host: *.example.com или app.example.com"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                />
                <input
                  v-model.number="wizard.priority"
                  type="number"
                  placeholder="Приоритет (по умолчанию 100, меньше — раньше в списке)"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                />
                <label class="flex items-center gap-2 text-sm text-slate-400">
                  <input v-model="wizard.enabled" type="checkbox" class="rounded border-slate-600" />
                  Сайт включён
                </label>
                <div>
                  <label class="text-xs text-slate-500">Политика WAF (необязательно)</label>
                  <select v-model="wizard.policy_id" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                    <option value="">Все включённые политики (по умолчанию)</option>
                    <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
                  </select>
                </div>
              </div>

              <div v-show="wizardStep === 2" class="space-y-3">
                <h3 class="text-sm font-medium text-slate-300">Бэкенд (upstream)</h3>
                <p class="text-xs text-slate-500">
                  Шлюз отправляет трафик на первый включённый бэкенд с наименьшим приоритетом.
                </p>
                <input
                  v-model="wizard.backend_name"
                  placeholder="Имя бэкенда"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                />
                <input
                  v-model="wizard.backend_url"
                  placeholder="Базовый URL, например http://app:3000 или https://upstream:443"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-xs"
                />
                <input
                  v-model.number="wizard.backend_priority"
                  type="number"
                  placeholder="Приоритет бэкенда (100 по умолчанию)"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                />
                <label class="flex items-center gap-2 text-sm text-amber-200/90">
                  <input v-model="wizard.tls_skip_verify" type="checkbox" class="rounded border-slate-600" />
                  Не проверять TLS-сертификат upstream (только для <span class="font-mono">https://</span> бэкенда; небезопасно)
                </label>
              </div>

              <div v-show="wizardStep === 3" class="space-y-3">
                <h3 class="text-sm font-medium text-slate-300">HTTPS (необязательно)</h3>
                <p class="text-xs text-slate-500">
                  Терминация TLS на waf-gateway по SNI. Сертификат должен покрывать тот же хост, что и шаблон сайта. Порты см. README
                  (HTTP <code class="text-slate-400">WAF_LISTEN_ADDR</code>, HTTPS <code class="text-slate-400">WAF_TLS_LISTEN_ADDR</code>).
                </p>
                <label class="flex items-center gap-2 text-sm text-slate-400">
                  <input v-model="wizard.tls_enabled" type="checkbox" class="rounded border-slate-600" />
                  Включить HTTPS для этого сайта после создания
                </label>
                <textarea
                  v-model="wizard.tls_cert_pem"
                  rows="6"
                  placeholder="-----BEGIN CERTIFICATE----- ... (полная цепочка PEM)"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
                />
                <textarea
                  v-model="wizard.tls_key_pem"
                  rows="4"
                  placeholder="-----BEGIN PRIVATE KEY----- ..."
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
                />
              </div>

              <div class="mt-6 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  class="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700"
                  :disabled="busy || wizardStep === 1"
                  @click="wizardStep--"
                >
                  Назад
                </button>
                <button
                  v-if="wizardStep < 3"
                  type="button"
                  class="rounded-lg bg-teal-600 px-4 py-2 text-sm text-white hover:bg-teal-500"
                  :disabled="busy"
                  @click="wizardNext"
                >
                  Далее
                </button>
                <button
                  v-else
                  type="button"
                  class="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500"
                  :disabled="busy"
                  @click="finalizeWizard"
                >
                  Создать сайт
                </button>
              </div>
            </div>
          </div>

          <!-- Редактирование -->
          <div v-else-if="sitePanelMode === 'edit' && selected" class="max-h-[min(85vh,calc(100vh-4rem))] overflow-y-auto p-6 sm:p-8">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div class="min-w-0">
                <h2 id="site-panel-title-edit" class="truncate text-lg font-semibold text-white">Редактирование: {{ selected.name }}</h2>
                <p class="mt-1 font-mono text-xs text-slate-500">{{ selected.host_pattern }}</p>
              </div>
              <button
                type="button"
                class="shrink-0 rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
                :disabled="busy"
                @click="closeSitePanel"
              >
                Закрыть
              </button>
            </div>

            <div class="mt-8 space-y-8">
              <div class="grid gap-8 lg:grid-cols-2">
                <div>
                  <h3 class="text-sm font-medium text-slate-300">Параметры сайта</h3>
                  <div class="mt-2 space-y-2">
                    <input v-model="edit.name" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
                    <input v-model="edit.host_pattern" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
                    <input v-model.number="edit.priority" type="number" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
                    <label class="flex items-center gap-2 text-sm text-slate-400">
                      <input v-model="edit.enabled" type="checkbox" class="rounded border-slate-600" />
                      Включён
                    </label>
                    <div>
                      <label class="text-xs text-slate-500">Политика WAF</label>
                      <select v-model="edit.policy_id" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                        <option value="">Все включённые политики</option>
                        <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
                      </select>
                    </div>
                    <div class="flex flex-wrap gap-2 pt-2">
                      <button type="button" class="rounded-lg bg-slate-700 px-3 py-2 text-sm hover:bg-slate-600" :disabled="busy" @click="saveSite">
                        Сохранить сайт
                      </button>
                      <button
                        type="button"
                        class="rounded-lg border border-rose-800 px-3 py-2 text-sm text-rose-300 hover:bg-rose-950/50"
                        :disabled="busy"
                        @click="deleteSite"
                      >
                        Удалить сайт
                      </button>
                    </div>
                  </div>
                </div>

                <div class="rounded-xl border border-white/5 bg-slate-950/40 p-4">
                  <h3 class="text-sm font-medium text-slate-300">HTTPS (TLS на шлюзе)</h3>
                  <p class="mt-1 text-xs text-slate-500">
                    Ключ и сертификат хранятся в БД; при сохранении шлюз подхватывает их без перезапуска. Содержимое сертификата по API не
                    отдаётся — при замене вставьте PEM заново.
                  </p>
                  <div class="mt-4 space-y-3">
                    <p class="text-xs text-slate-500">
                      Состояние:
                      <span v-if="tlsMeta.tls_has_certificate" class="text-emerald-400">сертификат загружен</span>
                      <span v-else class="text-amber-400/90">сертификат не задан</span>
                    </p>
                    <label class="flex items-center gap-2 text-sm text-slate-400">
                      <input v-model="tlsForm.enabled" type="checkbox" class="rounded border-slate-600" />
                      TLS включён для этого сайта
                    </label>
                    <textarea
                      v-model="tlsForm.cert_pem"
                      rows="5"
                      placeholder="PEM сертификата (цепочка), вставьте чтобы задать или обновить"
                      class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
                    />
                    <textarea
                      v-model="tlsForm.key_pem"
                      rows="3"
                      placeholder="Приватный ключ PEM (пусто = не менять существующий ключ)"
                      class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
                    />
                    <button type="button" class="rounded-lg bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-600" :disabled="busy" @click="saveTls">
                      Сохранить TLS
                    </button>
                  </div>
                </div>
              </div>

              <div>
                <h3 class="text-sm font-medium text-slate-300">Бэкенды (upstream)</h3>
                <ul class="mt-2 list-inside list-disc space-y-1 text-xs text-slate-500">
                  <li><strong class="text-slate-400">Upstream</strong> — один Base URL на бэкенд.</li>
                  <li><strong class="text-slate-400">Пути</strong> — <span class="font-mono">*</span> (все) и префиксы вроде <span class="font-mono">/admin</span>.</li>
                  <li>Длиннейший префикс побеждает; WS, таймауты и IP задаются на пути.</li>
                </ul>
                <p v-if="!backends.length" class="mt-4 rounded-lg border border-dashed border-slate-700 bg-slate-950/40 px-4 py-6 text-center text-sm text-slate-500">Нет upstream — добавьте ниже.</p>
                <div v-else class="mt-4 space-y-5">
                  <article v-for="b in backends" :key="b.id" class="rounded-xl border border-white/10 bg-slate-950/50 p-4">
                    <div class="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/80 pb-4">
                      <div class="min-w-0 flex-1">
                        <h4 class="font-medium text-slate-100">{{ b.name || 'Без имени' }}</h4>
                        <p class="mt-1 font-mono text-xs text-slate-500">{{ b.base_url }}</p>
                      </div>
                      <div class="flex gap-2">
                        <button type="button" class="rounded-lg bg-sky-700/80 px-3 py-1.5 text-xs text-white hover:bg-sky-600" :disabled="busy" @click="saveBackend(b)">Сохранить upstream</button>
                        <button type="button" class="rounded-lg border border-rose-800/80 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-950/40" :disabled="busy" @click="removeBackend(b)">Удалить</button>
                      </div>
                    </div>
                    <fieldset class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <legend class="col-span-full mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Upstream</legend>
                      <label class="block sm:col-span-2"><span class="text-xs text-slate-500">Имя</span><input v-model="b.name" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
                      <label class="block sm:col-span-2"><span class="text-xs text-slate-500">Base URL</span><input v-model="b.base_url" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" /></label>
                      <label class="block"><span class="text-xs text-slate-500">Приоритет</span><input v-model.number="b.priority" type="number" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
                      <label class="flex items-center gap-2 self-end text-sm text-slate-300"><input v-model="b.enabled" type="checkbox" class="rounded border-slate-600" /> Включён</label>
                      <label class="flex items-center gap-2 self-end text-sm text-amber-200/90 sm:col-span-2"><input v-model="b.tls_skip_verify" type="checkbox" class="rounded border-slate-600" /> Не проверять TLS</label>
                    </fieldset>
                    <div class="mt-6">
                      <h5 class="text-xs font-medium uppercase tracking-wide text-slate-500">Пути</h5>
                      <p v-if="!b.paths.length" class="mt-2 text-sm text-slate-500">Нет путей. Добавьте <span class="font-mono">*</span> или <span class="font-mono">/admin</span>.</p>
                      <div v-else class="mt-3 space-y-3">
                        <div v-for="p in b.paths" :key="p.id" class="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                          <div class="mb-2 flex items-center justify-between gap-2"><span class="font-mono text-sm text-sky-300">{{ pathPrefixLabel(p.path_prefix) }}</span><span class="text-[10px] text-slate-500">prio {{ p.priority }}</span></div>
                          <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                            <label class="block"><span class="text-xs text-slate-500">Префикс</span><input v-model="p.path_prefix" placeholder="* /admin" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs" /></label>
                            <label class="block"><span class="text-xs text-slate-500">Приоритет</span><input v-model.number="p.priority" type="number" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" /></label>
                            <label class="flex items-center gap-2 self-end text-sm text-teal-200/90"><input v-model="p.websocket_enabled" type="checkbox" class="rounded border-slate-600" /> WS</label>
                            <label class="flex items-center gap-2 self-end text-sm text-slate-300"><input v-model="p.enabled" type="checkbox" class="rounded border-slate-600" /> Вкл</label>
                            <label class="block"><span class="text-xs text-slate-500">Timeout</span><input v-model.number="p.timeout" type="number" min="0" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" /></label>
                            <label class="block"><span class="text-xs text-slate-500">Idle</span><input v-model.number="p.idle_timeout" type="number" min="0" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" /></label>
                            <label class="block sm:col-span-2"><span class="text-xs text-slate-500">IP</span><select v-model="p.ip_allow_mode" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm"><option value="none">Любой</option><option value="private">Приватные</option><option value="custom">CIDR</option></select></label>
                            <label v-if="p.ip_allow_mode === 'custom'" class="block sm:col-span-2 lg:col-span-4"><span class="text-xs text-slate-500">CIDR</span><textarea v-model="p.allowed_cidrs_text" rows="2" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs" /></label>
                          </div>
                          <div class="mt-2 flex gap-3"><button type="button" class="text-xs text-sky-400 hover:underline" @click="saveBackendPath(p)">Сохранить</button><button type="button" class="text-xs text-rose-400 hover:underline" @click="removeBackendPath(p)">Удалить</button></div>
                        </div>
                      </div>
                      <div class="mt-4 rounded-lg border border-dashed border-slate-700 bg-slate-950/30 p-3">
                        <p class="text-xs text-slate-400">Новый путь</p>
                        <div class="mt-2 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                          <label class="block"><span class="text-xs text-slate-500">Префикс</span><input v-model="pathDraft(b.id).path_prefix" placeholder="* /admin" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs" /></label>
                          <label class="block"><span class="text-xs text-slate-500">Приоритет</span><input v-model.number="pathDraft(b.id).priority" type="number" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm" /></label>
                          <label class="flex items-center gap-2 self-end text-sm text-teal-200/90"><input v-model="pathDraft(b.id).websocket_enabled" type="checkbox" class="rounded border-slate-600" /> WS</label>
                          <label class="block"><span class="text-xs text-slate-500">IP</span><select v-model="pathDraft(b.id).ip_allow_mode" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm"><option value="none">Любой</option><option value="private">Приватные</option><option value="custom">CIDR</option></select></label>
                          <label v-if="pathDraft(b.id).ip_allow_mode === 'custom'" class="block sm:col-span-2 lg:col-span-4"><span class="text-xs text-slate-500">CIDR</span><textarea v-model="pathDraft(b.id).allowed_cidrs_text" rows="2" class="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 font-mono text-xs" /></label>
                        </div>
                        <button type="button" class="mt-2 rounded bg-teal-800/80 px-3 py-1.5 text-xs text-teal-100" :disabled="busy" @click="addBackendPath(b.id)">Добавить путь</button>
                      </div>
                    </div>
                  </article>
                </div>
                <article class="mt-6 rounded-xl border border-dashed border-teal-800/40 bg-teal-950/10 p-4">
                  <h4 class="text-sm font-medium text-teal-100">Новый upstream</h4>
                  <p class="mt-1 text-xs text-slate-500">Создаётся с путём <span class="font-mono">*</span> по умолчанию.</p>
                  <div class="mt-4 grid gap-3 sm:grid-cols-2">
                    <label class="block"><span class="text-xs text-slate-500">Имя</span><input v-model="newBackend.name" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
                    <label class="block"><span class="text-xs text-slate-500">Base URL</span><input v-model="newBackend.base_url" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs" /></label>
                    <label class="block"><span class="text-xs text-slate-500">Приоритет</span><input v-model.number="newBackend.priority" type="number" class="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /></label>
                    <label class="flex items-center gap-2 self-end text-sm text-amber-200/90"><input v-model="newBackend.tls_skip_verify" type="checkbox" class="rounded border-slate-600" /> TLS skip</label>
                  </div>
                  <div class="mt-4 flex justify-end"><button type="button" class="rounded-lg bg-emerald-600 px-5 py-2 text-sm text-white hover:bg-emerald-500" :disabled="busy" @click="addBackend">Добавить upstream</button></div>
                </article>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import type { FetchError } from 'ofetch'

const { apiUrl } = useApi()

type Site = {
  id: string
  name: string
  host_pattern: string
  priority: number
  enabled: boolean
  policy_id: string
  tls_enabled: boolean
  tls_has_certificate: boolean
}
type IPAllowMode = 'none' | 'private' | 'custom'

type BackendPath = {
  id: string
  backend_id: string
  path_prefix: string
  priority: number
  enabled: boolean
  websocket_enabled: boolean
  timeout: number
  idle_timeout: number
  ip_allow_mode: IPAllowMode
  allowed_cidrs_text: string
}

type Backend = {
  id: string
  name: string
  base_url: string
  priority: number
  enabled: boolean
  tls_skip_verify: boolean
  paths: BackendPath[]
}

const stepLabels = ['Сайт', 'Бэкенд', 'HTTPS']

const err = ref('')
const ok = ref('')
const busy = ref(false)
const sitePanelOpen = ref(false)
const sitePanelMode = ref<'create' | 'edit'>('create')
const sites = ref<Site[]>([])
const selectedId = ref('')
const selected = computed(() => sites.value.find((s) => s.id === selectedId.value) ?? null)
const policies = ref<{ id: string; name: string }[]>([])
const edit = reactive({ name: '', host_pattern: '', priority: 100, enabled: true, policy_id: '' })
const backends = ref<Backend[]>([])

const wizardStep = ref(1)
const wizard = reactive({
  name: '',
  host_pattern: '',
  priority: 0,
  enabled: true,
  policy_id: '',
  backend_name: '',
  backend_url: '',
  backend_priority: 0,
  tls_skip_verify: false,
  tls_enabled: false,
  tls_cert_pem: '',
  tls_key_pem: '',
})

const tlsMeta = reactive({ tls_enabled: false, tls_has_certificate: false })
const tlsForm = reactive({ enabled: false, cert_pem: '', key_pem: '' })

const newBackend = reactive({
  name: '',
  base_url: '',
  priority: 0,
  tls_skip_verify: false,
})

type PathDraft = {
  path_prefix: string
  priority: number
  websocket_enabled: boolean
  timeout: number
  idle_timeout: number
  ip_allow_mode: IPAllowMode
  allowed_cidrs_text: string
}

const pathDrafts = reactive<Record<string, PathDraft>>({})

function pathDraft(backendId: string): PathDraft {
  if (!pathDrafts[backendId]) {
    pathDrafts[backendId] = {
      path_prefix: '*',
      priority: 100,
      websocket_enabled: false,
      timeout: 0,
      idle_timeout: 0,
      ip_allow_mode: 'none',
      allowed_cidrs_text: '',
    }
  }
  return pathDrafts[backendId]
}

function flashErr(e: unknown) {
  ok.value = ''
  const fe = e as FetchError<{ error?: string }>
  err.value = fe?.data?.error || fe?.message || String(e)
}

function flashOk(msg: string) {
  err.value = ''
  ok.value = msg
  setTimeout(() => {
    ok.value = ''
  }, 4000)
}

function normSite(raw: Record<string, unknown>): Site {
  return {
    id: String(raw.id ?? raw.ID),
    name: String(raw.name ?? raw.Name),
    host_pattern: String(raw.host_pattern ?? raw.HostPattern),
    priority: Number(raw.priority ?? raw.Priority),
    enabled: Boolean(raw.enabled ?? raw.Enabled),
    policy_id: String(raw.policy_id ?? raw.PolicyID ?? ''),
    tls_enabled: Boolean(raw.tls_enabled ?? raw.TLSEnabled ?? false),
    tls_has_certificate: Boolean(raw.tls_has_certificate ?? raw.TLSHasCertificate ?? false),
  }
}

function ipAllowLabel(mode: string): string {
  switch (mode) {
    case 'private':
      return 'Приватные'
    case 'custom':
      return 'CIDR'
    default:
      return 'Любой IP'
  }
}

function parseIPCIDRMultiline(text: string): string[] {
  return [...new Set(text.split(/[\s,;\n\r]+/).map((s) => s.trim()).filter(Boolean))]
}

function cidrsToText(list: unknown): string {
  if (!Array.isArray(list)) return ''
  return list.map((x) => String(x).trim()).filter(Boolean).join('\n')
}

function pathIPPayload(p: Pick<BackendPath, 'ip_allow_mode' | 'allowed_cidrs_text'>) {
  const mode = p.ip_allow_mode || 'none'
  return {
    ip_allow_mode: mode,
    allowed_cidrs: mode === 'custom' ? parseIPCIDRMultiline(p.allowed_cidrs_text) : [],
  }
}

function pathPrefixLabel(prefix: string): string {
  const p = prefix.trim()
  if (!p || p === '*') return '*'
  return p
}

function normBackendPath(raw: Record<string, unknown>): BackendPath {
  const mode = String(raw.ip_allow_mode ?? raw.IPAllowMode ?? 'none').toLowerCase()
  const ipMode: IPAllowMode = mode === 'private' || mode === 'custom' ? mode : 'none'
  return {
    id: String(raw.id ?? raw.ID),
    backend_id: String(raw.backend_id ?? raw.BackendID ?? ''),
    path_prefix: String(raw.path_prefix ?? raw.PathPrefix ?? '*') || '*',
    priority: Number(raw.priority ?? raw.Priority ?? 100),
    enabled: Boolean(raw.enabled ?? raw.Enabled ?? true),
    websocket_enabled: Boolean(raw.websocket_enabled ?? raw.websocketEnabled ?? raw.WebSocketEnabled ?? false),
    timeout: Number(raw.timeout ?? raw.Timeout ?? 0),
    idle_timeout: Number(raw.idle_timeout ?? raw.idleTimeout ?? raw.IdleTimeout ?? 0),
    ip_allow_mode: ipMode,
    allowed_cidrs_text: cidrsToText(raw.allowed_cidrs ?? raw.AllowedCIDRs),
  }
}

function normBackend(raw: Record<string, unknown>): Backend {
  const pathsRaw = raw.paths ?? raw.Paths
  const paths = Array.isArray(pathsRaw) ? pathsRaw.map((p) => normBackendPath(p as Record<string, unknown>)) : []
  return {
    id: String(raw.id ?? raw.ID),
    name: String(raw.name ?? raw.Name),
    base_url: String(raw.base_url ?? raw.BaseURL),
    priority: Number(raw.priority ?? raw.Priority),
    enabled: Boolean(raw.enabled ?? raw.Enabled),
    tls_skip_verify: Boolean(raw.tls_skip_verify ?? raw.tlsSkipVerify ?? raw.TLSSkipVerify ?? false),
    paths,
  }
}

function resetPathDraft(backendId: string) {
  pathDrafts[backendId] = {
    path_prefix: '*',
    priority: 100,
    websocket_enabled: false,
    timeout: 0,
    idle_timeout: 0,
    ip_allow_mode: 'none',
    allowed_cidrs_text: '',
  }
}

function policyLabel(policyId: string) {
  if (!policyId) return 'по умолчанию'
  const p = policies.value.find((x) => x.id === policyId)
  return p?.name ?? policyId
}

function openAddWizard() {
  resetWizard()
  sitePanelMode.value = 'create'
  sitePanelOpen.value = true
}

function openEditModal(s: Site) {
  applySelection(s.id)
  sitePanelMode.value = 'edit'
  sitePanelOpen.value = true
}

function closeSitePanel() {
  sitePanelOpen.value = false
  resetWizard()
}

function resetWizard() {
  wizardStep.value = 1
  wizard.name = ''
  wizard.host_pattern = ''
  wizard.priority = 0
  wizard.enabled = true
  wizard.policy_id = ''
  wizard.backend_name = ''
  wizard.backend_url = ''
  wizard.backend_priority = 0
  wizard.tls_skip_verify = false
  wizard.tls_enabled = false
  wizard.tls_cert_pem = ''
  wizard.tls_key_pem = ''
}

function goWizardStep(n: number) {
  if (n >= 1 && n <= 3) wizardStep.value = n
}

function wizardNext() {
  if (wizardStep.value === 1) {
    if (!wizard.name.trim() || !wizard.host_pattern.trim()) {
      flashErr(new Error('Укажите название и шаблон хоста'))
      return
    }
  }
  if (wizardStep.value === 2) {
    if (!wizard.backend_name.trim() || !wizard.backend_url.trim()) {
      flashErr(new Error('Укажите имя и URL бэкенда'))
      return
    }
  }
  if (wizardStep.value === 3) {
    return
  }
  wizardStep.value++
}

async function finalizeWizard() {
  if (!wizard.name.trim() || !wizard.host_pattern.trim()) {
    wizardStep.value = 1
    flashErr(new Error('Укажите название и шаблон хоста'))
    return
  }
  if (!wizard.backend_name.trim() || !wizard.backend_url.trim()) {
    wizardStep.value = 2
    flashErr(new Error('Укажите имя и URL бэкенда'))
    return
  }
  if (wizard.tls_enabled && (!wizard.tls_cert_pem.trim() || !wizard.tls_key_pem.trim())) {
    flashErr(new Error('Для HTTPS нужны PEM сертификата и ключа'))
    return
  }

  const withTls = wizard.tls_enabled
  busy.value = true
  err.value = ''
  try {
    const siteRes = await $fetch<{ id: string }>(apiUrl('/sites'), {
      method: 'POST',
      body: {
        name: wizard.name.trim(),
        host_pattern: wizard.host_pattern.trim(),
        priority: wizard.priority || undefined,
        enabled: wizard.enabled,
        policy_id: wizard.policy_id || undefined,
      },
    })
    const siteId = siteRes.id
    await $fetch(apiUrl(`/sites/${siteId}/backends`), {
      method: 'POST',
      body: {
        name: wizard.backend_name.trim(),
        base_url: wizard.backend_url.trim(),
        priority: wizard.backend_priority || undefined,
        enabled: true,
        tls_skip_verify: wizard.tls_skip_verify,
      },
    })
    if (withTls) {
      await $fetch(apiUrl(`/sites/${siteId}/tls`), {
        method: 'PUT',
        body: {
          tls_enabled: true,
          tls_cert_pem: wizard.tls_cert_pem.trim(),
          tls_key_pem: wizard.tls_key_pem.trim(),
        },
      })
    }
    resetWizard()
    sitePanelOpen.value = false
    await loadSites()
    if (siteId) applySelection(siteId)
    flashOk('Сайт и бэкенд созданы' + (withTls ? ', TLS включён' : ''))
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function loadPolicies() {
  const data = await $fetch<{ items: { id: string; name: string }[] }>(apiUrl('/policies'))
  policies.value = data.items || []
}

function pickDefaultSite(list: Site[]): Site | null {
  if (!list.length) return null
  const star = list.find((s) => s.host_pattern === '*')
  if (star) return star
  const named = list.find((s) => s.name === 'default')
  if (named) return named
  return list[0] ?? null
}

async function loadSites() {
  busy.value = true
  err.value = ''
  const prevId = selectedId.value
  try {
    const data = await $fetch<{ items: Record<string, unknown>[] }>(apiUrl('/sites'))
    sites.value = (data.items || []).map(normSite)
    const still = prevId && sites.value.some((s) => s.id === prevId)
    if (still) {
      applySelection(prevId)
    } else if (sites.value.length) {
      const pick = pickDefaultSite(sites.value)
      if (pick) applySelection(pick.id)
    } else {
      selectedId.value = ''
      backends.value = []
    }
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function loadBackends(siteId: string) {
  const data = await $fetch<{ items: Record<string, unknown>[] }>(apiUrl(`/sites/${siteId}/backends`))
  backends.value = (data.items || []).map(normBackend)
}

async function loadTlsMeta(siteId: string) {
  try {
    const data = await $fetch<{ tls_enabled: boolean; tls_has_certificate: boolean }>(apiUrl(`/sites/${siteId}/tls`))
    tlsMeta.tls_enabled = data.tls_enabled
    tlsMeta.tls_has_certificate = data.tls_has_certificate
    tlsForm.enabled = data.tls_enabled
    tlsForm.cert_pem = ''
    tlsForm.key_pem = ''
  } catch (e) {
    flashErr(e)
  }
}

function applySelection(siteId: string) {
  const s = sites.value.find((x) => x.id === siteId)
  if (!s) return
  selectedId.value = siteId
  edit.name = s.name
  edit.host_pattern = s.host_pattern
  edit.priority = s.priority
  edit.enabled = s.enabled
  edit.policy_id = s.policy_id || ''
  loadBackends(siteId).catch(flashErr)
  loadTlsMeta(siteId).catch(flashErr)
}

function selectSite(s: Site) {
  sitePanelOpen.value = false
  applySelection(s.id)
}

async function saveSite() {
  if (!selected.value) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}`), {
      method: 'PUT',
      body: {
        name: edit.name,
        host_pattern: edit.host_pattern,
        priority: edit.priority,
        enabled: edit.enabled,
        policy_id: edit.policy_id || '',
      },
    })
    await loadSites()
    flashOk('Сайт сохранён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function deleteSite() {
  if (!selected.value) return
  if (!confirm('Удалить этот сайт и все его бэкенды?')) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}`), { method: 'DELETE' })
    selectedId.value = ''
    backends.value = []
    sitePanelOpen.value = false
    await loadSites()
    flashOk('Сайт удалён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveTls() {
  if (!selected.value) return

  if (!tlsForm.enabled) {
    busy.value = true
    err.value = ''
    try {
      await $fetch(apiUrl(`/sites/${selected.value.id}/tls`), { method: 'PUT', body: { tls_enabled: false } })
      tlsForm.cert_pem = ''
      tlsForm.key_pem = ''
      await loadSites()
      await loadTlsMeta(selected.value.id)
      flashOk('TLS отключён')
    } catch (e) {
      flashErr(e)
    } finally {
      busy.value = false
    }
    return
  }

  if (!tlsMeta.tls_has_certificate) {
    if (!tlsForm.cert_pem.trim() || !tlsForm.key_pem.trim()) {
      flashErr(new Error('При первом включении TLS укажите PEM сертификата и ключа'))
      return
    }
  }

  busy.value = true
  err.value = ''
  try {
    const body: Record<string, unknown> = { tls_enabled: true }
    if (tlsForm.cert_pem.trim()) body.tls_cert_pem = tlsForm.cert_pem.trim()
    if (tlsForm.key_pem.trim()) body.tls_key_pem = tlsForm.key_pem.trim()
    await $fetch(apiUrl(`/sites/${selected.value.id}/tls`), { method: 'PUT', body })
    tlsForm.cert_pem = ''
    tlsForm.key_pem = ''
    await loadSites()
    await loadTlsMeta(selected.value.id)
    flashOk('Настройки TLS сохранены')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveBackend(b: Backend) {
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backends/${b.id}`), {
      method: 'PUT',
      body: {
        name: b.name,
        base_url: b.base_url,
        priority: b.priority,
        enabled: b.enabled,
        tls_skip_verify: b.tls_skip_verify,
      },
    })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Upstream сохранён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function saveBackendPath(p: BackendPath) {
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backend-paths/${p.id}`), {
      method: 'PUT',
      body: {
        path_prefix: p.path_prefix,
        priority: p.priority,
        enabled: p.enabled,
        websocket_enabled: p.websocket_enabled,
        timeout: p.timeout,
        idle_timeout: p.idle_timeout,
        ...pathIPPayload(p),
      },
    })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Путь сохранён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function removeBackendPath(p: BackendPath) {
  if (!confirm(`Удалить путь ${pathPrefixLabel(p.path_prefix)}?`)) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backend-paths/${p.id}`), { method: 'DELETE' })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Путь удалён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function addBackendPath(backendId: string) {
  const draft = pathDraft(backendId)
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backends/${backendId}/paths`), {
      method: 'POST',
      body: {
        path_prefix: draft.path_prefix,
        priority: draft.priority || undefined,
        enabled: true,
        websocket_enabled: draft.websocket_enabled,
        timeout: draft.timeout,
        idle_timeout: draft.idle_timeout,
        ...pathIPPayload(draft),
      },
    })
    resetPathDraft(backendId)
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Путь добавлен')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function removeBackend(b: Backend) {
  if (!confirm('Удалить этот бэкенд?')) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/backends/${b.id}`), { method: 'DELETE' })
    if (selected.value) await loadBackends(selected.value.id)
    flashOk('Бэкенд удалён')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

async function addBackend() {
  if (!selected.value) return
  busy.value = true
  err.value = ''
  try {
    await $fetch(apiUrl(`/sites/${selected.value.id}/backends`), {
      method: 'POST',
      body: {
        name: newBackend.name,
        base_url: newBackend.base_url,
        priority: newBackend.priority || undefined,
        enabled: true,
        tls_skip_verify: newBackend.tls_skip_verify,
      },
    })
    newBackend.name = ''
    newBackend.base_url = ''
    newBackend.priority = 0
    newBackend.tls_skip_verify = false
    await loadBackends(selected.value.id)
    flashOk('Бэкенд добавлен')
  } catch (e) {
    flashErr(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  loadPolicies().catch(flashErr)
  loadSites().catch(flashErr)
})

function onSitePanelEscape(e: KeyboardEvent) {
  if (e.key !== 'Escape' || !sitePanelOpen.value) return
  e.preventDefault()
  closeSitePanel()
}

watch(sitePanelOpen, (open) => {
  if (typeof window === 'undefined') return
  if (open) window.addEventListener('keydown', onSitePanelEscape)
  else window.removeEventListener('keydown', onSitePanelEscape)
})

onUnmounted(() => {
  if (typeof window !== 'undefined') window.removeEventListener('keydown', onSitePanelEscape)
})
</script>
