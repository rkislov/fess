# Руководство администратора FESS (Frontend Security Server)

Документ описывает развёртывание, конфигурацию через `.env`, ежедневную работу в панели управления и типовые сценарии эксплуатации.

Связанные материалы:

- [README.md](../README.md) — обзор архитектуры и быстрый старт
- [deploy/.env.example](../deploy/.env.example) — шаблон всех переменных окружения
- [openapi.yaml](./openapi.yaml) — REST API (OpenAPI 3.0, версия **1.1.1**; с policy-api: `GET /api/v1/openapi.yaml`)
- [blueprint.md](./blueprint.md) — план развития и компоненты

---

## 1. Архитектура

| Компонент | Назначение |
|-----------|------------|
| **waf-gateway** | Reverse proxy, проверка правил WAF, ICAP/сканеры, GeoIP, запись журналов |
| **policy-api** | REST API, миграции БД, публикация политик и маршрутизации в Redis |
| **ui** | Статическая панель (Nginx), проксирует `/api/*` на policy-api |
| **PostgreSQL** | Политики, сайты, журналы, настройки |
| **Redis** | Pub/sub: `policy_updated`, `routing_updated`, `malware_settings_updated`, `geoip_mmdb_updated` |
| **clamav-icap** (опционально) | ClamAV + c-icap для REQMOD |

**Живое обновление без перезапуска шлюза:** после публикации политики или сохранения настроек malware policy-api публикует событие в Redis; все экземпляры `waf-gateway` подхватывают снимок в памяти.

---

## 2. Быстрый старт с `.env`

```bash
cd /path/to/fence
cp deploy/.env.example deploy/.env
# Отредактируйте deploy/.env: пароли, FENCE_JWT_SECRET, при необходимости FENCE_AI_API_KEY

docker compose -f deploy/docker-compose.yml up -d --build
```

Нужен **Compose V2** (`docker compose`). Если установлена только связка `docker-compose` (v1), будет ошибка про ключ `name` или `KeyError: 'id'` — поставьте плагин Compose: `docker compose version`.

После старта:

| Сервис | URL по умолчанию |
|--------|------------------|
| Панель UI | http://localhost:5173 |
| WAF (HTTP) | http://localhost:8080 |
| WAF (HTTPS) | https://localhost:8443 |
| Policy API | http://localhost:8082 |
| Метрики gateway | http://localhost:9091/metrics |
| Метрики policy-api | http://localhost:9092/metrics |

**Первый вход в API:** при пустой таблице `users` создаётся пользователь `admin` с паролем `fessfess` (смените в UI → Настройки → Пользователи). Экран входа **не** показывает логин и пароль.

**Демо-экран UI:** `FENCE_UI_*` используются только для тихого входа, если `FENCE_UI_AUTH_ENABLED=false` (см. раздел 8).

---

## 3. Переменные окружения (полный справочник)

Все параметры для Docker Compose собраны в `deploy/.env.example`. Ниже — смысл групп.

### 3.1. Инфраструктура

| Переменная | Сервис | Описание |
|------------|--------|----------|
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | postgres | Учётная запись БД |
| `POSTGRES_DSN` | policy-api, waf-gateway | Строка подключения Go (`sslmode=disable` внутри compose-сети) |
| `REDIS_ADDR` | policy-api, waf-gateway | Адрес Redis (`host:port`) |
| `FENCE_*_PORT` | compose | Проброс портов на хост |

### 3.2. policy-api

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `POLICY_API_LISTEN_ADDR` | `:8082` | HTTP API |
| `POLICY_API_METRICS_ADDR` | `:9092` | Prometheus `/metrics` |
| `FENCE_GEOIP_DATA_DIR` | `/var/lib/fence/geoip` | Каталог для `.mmdb` (общий том с gateway) |
| `FENCE_SKIP_DB_MIGRATE` | — | `1` — не применять `db/NNN_*.sql` при старте |
| `FENCE_METRICS_DB_INTERVAL` | — | Период опроса БД для метрик (например `30s`) |
| `CLAMAV_CLAMD_PORT` | `0` | TCP-порт clamd для probe `VERSION` в UI; `0` = отключено |
| `FENCE_JWT_SECRET` | — | **Обязателен в проде** — подпись JWT |
| `FENCE_AUTH_DISABLED` | — | `1`/`true` — API без авторизации (только отладка) |
| `FENCE_ACCESS_TOKEN_TTL` | `15m` | Время жизни access token |
| `FENCE_REFRESH_TOKEN_TTL` | `168h` | Refresh token |
| `FENCE_AI_API_KEY` | — | Ключ OpenAI-совместимого API |
| `FENCE_AI_BASE_URL` | `https://api.openai.com/v1` | Базовый URL API |
| `FENCE_AI_MODEL` | `gpt-4o-mini` | Имя модели |
| `FENCE_AI_HTTP_TIMEOUT` | `10m` | Таймаут запросов к модели |

Значения ИИ из env используются, пока в БД (`ai_settings`) соответствующие поля пустые; UI может переопределить.

### 3.3. waf-gateway

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `WAF_LISTEN_ADDR` | `:8080` | HTTP listener |
| `WAF_TLS_LISTEN_ADDR` | `:8443` | HTTPS (SNI + PEM из БД); пусто = только HTTP |
| `UPSTREAM_URL` | пусто | Если Host не совпал ни с одним сайтом — заставка FESS (стрит-арт). Укажите URL, только если нужен запасной reverse-proxy. |
| `WAF_FAIL_MODE` | `open` | `open` — при недоступности policy/Redis пропускать; `closed` — 503 |
| `WAF_TRUSTED_PROXIES` | см. example | CIDR **TCP-пиров** к шлюзу (Nginx/LB) для разбора X-Forwarded-For |
| `WAF_METRICS_ADDR` | `:9091` | Prometheus |
| `GEOIP_MMDB_PATH` | путь к Country `.mmdb` | Страна в журнале соединений и на карте |
| `GEOIP_ASN_MMDB_PATH` | путь к ASN `.mmdb` | Опционально |

### 3.4. UI (аргументы сборки)

| Переменная | Описание |
|------------|----------|
| `NUXT_PUBLIC_API_BASE` | Префикс API (обычно `/api/v1`) |
| `FENCE_UI_AUTH_ENABLED` | `false` — скрыть демо-форму входа в браузере |
| `FENCE_UI_USER`, `FENCE_UI_PASSWORD` | Учётные данные демо-экрана (вшиваются в bundle) |

После изменения `FENCE_UI_*` или `NUXT_PUBLIC_API_BASE` нужна **пересборка** образа `ui`.

---

## 4. Что настраивается только в UI / БД

Эти параметры **не** выносятся в `.env` (хранятся в PostgreSQL, живое обновление через Redis):

| Раздел UI | Таблица / сущность | Назначение |
|-----------|-------------------|------------|
| Политики / правила | `policies`, `rules` | WAF: условия, действия block/log |
| Сайты и бэкенды | `sites`, `backends` | Виртуальные хосты, upstream, TLS PEM |
| Антивирус | `malware_settings` | ICAP, внешний HTTP-сканер, fail_open, MIME |
| ThreatFox / IOC | `threat_feed_settings` | Auth-Key, синхронизация IP и хэшей |
| ИИ | `ai_settings` | Переопределение `FENCE_AI_*` |
| Пользователи / LDAP | `users`, `auth_settings` | RBAC, LDAP |
| SIEM | `siem_export_settings` | TCP syslog / CEF |
| IP bypass | `ip_bypass_rules` | Исключения из WAF |
| Оформление UI | `localStorage` (`fess-ui-theme`) | Светлая / тёмная / как в системе; стрит-арт остаётся фоном |
| Bot protection | настройки сайта | Защита от ботов |
| Rate limit | `rate_limit_settings`, `backends.rate_limit_override`, `backend_paths.rate_limit_override` | Лимит RPS: система → бэкенд → путь |

---

## 5. Rate limit (иерархия)

Лимит запросов считается в Redis и применяется на **waf-gateway** до антивируса и WAF-правил (кроме IP из обхода).

**Приоритет настроек:**

1. **Путь** (`backend_paths.rate_limit_override`) — если задан переопределение.
2. Иначе **бэкенд** (`backends.rate_limit_override`).
3. Иначе **система** (UI → **Настройки → Rate limit**, таблица `rate_limit_settings`).

Пустое переопределение (`inherit` / `null` в API) означает «наследовать уровень выше».

| Поле | Описание |
|------|----------|
| `enabled` | Включить лимит на этом уровне |
| `requests_per_window` | Максимум запросов за окно |
| `window_sec` | Длина окна в секундах |
| `scope` | Ключ счётчика: `ip`, `ip_host`, `ip_path`, `backend` |

API: `GET/PUT /api/v1/settings/rate-limit`. При сохранении системных настроек шлюз получает событие Redis `rate_limit_updated`; при изменении бэкенда/пути — `routing_updated`.

При превышении лимита: HTTP **429**, запись в `waf_logs` с `action=rate_limit`, исход в `proxy_access_logs`: `rate_limit`.

---

## 6. Политики и правила WAF

1. **Политики** → создать политику (`mode`: `block` / `log`, `priority`).
2. **Правила** → условия в JSON (`condition_json`): заголовки, путь, IP, тело и т.д.
3. **Публикация** → `POST .../policies/{id}/publish` или кнопка в UI — шлюз получает снимок.

**OWASP-пакеты:** `GET /api/v1/owasp/packs`, импорт `POST /api/v1/owasp/import` с `pack_id` (`crs-bundle-v1`, `crs-lite-v1`).

**Быстрые действия:** из карточки события WAF — enable/disable/log_only/block для правила с автопубликацией.

---

## 6. Сайты, TLS и маршрутизация

- **host_pattern:** точный хост, `*.example.com` или `*`.
- **priority:** меньшее число — раньше в цепочке.
- **policy_id:** если задан — только эта политика; иначе все включённые.
- **Бэкенды:** `base_url` (`http://` / `https://`), `tls_skip_verify` для lab.
- **TLS на шлюзе:** PEM цепочка + ключ в записи сайта; listener `WAF_TLS_LISTEN_ADDR`.
- На границе сети: `80:8080`, `443:8443` на сервис `waf-gateway`.
- Если Host не совпал — HTML-заставка FESS (стрит-арт, автор Роман Сергеевич Кислов). Те же муралы на страницах 403/429/502/503 и challenge ботов. Демо-контейнер httpbin из стека убран.

Публикация маршрутизации: Redis `routing_updated`.

---

## 7. Антивирус (ICAP и HTTP-сканер)

**По умолчанию в compose:** сервис `clamav-icap`, порт **1344**, сервис ICAP `avscan`.

В UI (**Антивирус**):

- Включить ICAP, хост `clamav-icap`, порт 1344.
- **fail_open:** при сбое ICAP пропускать или блокировать.
- **external_scanner.url** — второй слой (multipart HTTP), опционально.

Первый старт ClamAV может занять несколько минут (загрузка сигнатур).

**Статус:** `GET /api/v1/settings/malware/status` — ICAP, clamd (если `CLAMAV_CLAMD_PORT≠0`), внешний сканер.

**Журнал:** `GET /api/v1/malware-scan-logs` (фильтры `result`, `source`, `q`, `hours`).

---

## 8. Аутентификация

### 8.1. API (JWT)

- Логин: `POST /api/v1/auth/login` → access + refresh token.
- Заголовок: `Authorization: Bearer <access>`.
- Роли: `admin`, `operator`, `viewer`.

В продакшене:

1. Задайте длинный `FENCE_JWT_SECRET` в `.env`.
2. Не включайте `FENCE_AUTH_DISABLED`.
3. Смените пароль `admin` после первого входа.

### 8.2. LDAP

Настройки в UI → **Настройки → Аутентификация** (`auth_settings`): URL, bind DN, base DN, фильтр.

### 8.3. Демо-экран UI

`FENCE_UI_*` — только клиентская проверка в статическом SPA. Для продакшена используйте JWT API и/или SSO на reverse proxy; при внешней аутентификации можно `FENCE_UI_AUTH_ENABLED=false`.

---

## 9. ThreatFox, Q-Feeds и FESS Feed

UI → **Настройки → IOC**:

- **FESS Feed** (рекомендуется для подписки): базовый URL `https://feed.kislovs.ru`, ключ из кабинета [feed.kislovs.ru](https://feed.kislovs.ru). Текстовые файлы IP и хэшей; зеркало ClamAV — `https://feed.kislovs.ru/clamav/<ключ>` в **Антивирус → ClamAV mirror**.
- **ThreatFox** — свой Auth-Key abuse.ch.
- **URL / Q-Feeds** — свой токен и URL.

API: `POST /api/v1/settings/threat-feed/sync`, `POST .../threatfox/full`.

---

## 10. GeoIP

1. Загрузите **GeoLite2-Country.mmdb** (и при необходимости ASN) через UI (**Антивирус → GeoIP**) или скопируйте в том `fence_geoip_data`.
2. Пути должны совпадать с `GEOIP_MMDB_PATH` / `GEOIP_ASN_MMDB_PATH` на gateway.
3. После обновления файла policy-api шлёт `geoip_mmdb_updated` — перезапуск gateway не нужен.

Альтернатива: заголовок `CF-IPCountry` от Cloudflare.

---

## 11. ИИ-помощник

- Env: `FENCE_AI_*` (см. §3.2).
- UI: **Настройки → ИИ** — модель, URL, ключ, таймаут.
- **Дашборд / срабатывания:** анализ логов и событий; ответы **не применяют** правила автоматически.

При таймаутах увеличьте `FENCE_AI_HTTP_TIMEOUT` или значение в UI.

---

## 12. SIEM

UI → **Настройки → SIEM**: TCP хост/порт, формат CEF/syslog, включение потоков WAF / proxy / audit.

Экспортёр в policy-api отправляет новые строки по курсору в `siem_export_cursors`.

---

## 13. Журналы и мониторинг

| Журнал | API | Кто пишет |
|--------|-----|-----------|
| Срабатывания правил | `GET /api/v1/logs`, `GET /api/v1/waf-log-events` | waf-gateway |
| Соединения | `GET /api/v1/proxy-access-logs` | waf-gateway |
| Антивирус | `GET /api/v1/malware-scan-logs` | waf-gateway |

Общие query-параметры: `q` (поиск по полям), `hours` (`0` = всё время), фильтры по колонкам (см. README).

**Дашборд:** RPS, топ правил, карта (нужен GeoIP). Блок **«Состояние платформы FESS»** — CPU/память/load хоста и список контейнеров compose. Сокет `FENCE_DOCKER_SOCK` смонтирован в policy-api; процесс `appuser` входит в группу `root`, чтобы читать сокет Docker Desktop (`root:root` 660). На Linux задайте **`DOCKER_GID`** (`stat -c '%g' /var/run/docker.sock`). Проект Compose: `fess`.

**Prometheus:** `/metrics` на портах 9091 (gateway) и 9092 (policy-api).

---

## 14. Nginx перед waf-gateway

`WAF_TRUSTED_PROXIES` — CIDR того, кто **TCP-подключается к шлюзу** (часто подсеть Docker или IP Nginx). Это **не** то же самое, что `set_real_ip_from` в Nginx.

На Nginx к upstream Fence:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

Подсказка: оставьте `WAF_TRUSTED_PROXIES` пустым, сделайте запрос, посмотрите колонку **TCP пир** в журнале соединений — эту подсеть добавьте в trusted.

---

## 15. Миграции БД

- При старте **policy-api** применяет `db/NNN_*.sql` (встроены в бинарник), версии в `fence_schema_migrations`.
- Новая миграция: добавить файл `db/030_....sql`, пересобрать policy-api.
- Init-скрипты Postgres в compose — для **новых** томов; с существующим томом достаточно automigrate.
- Аварийно: `FENCE_SKIP_DB_MIGRATE=1`.

**Сброс данных:** `docker compose ... down -v` (удаляет именованные тома).

---

## 16. Чеклист продакшена

- [ ] Уникальные `POSTGRES_PASSWORD`, `FENCE_JWT_SECRET`
- [ ] `FENCE_AUTH_DISABLED` не установлен
- [ ] Пароль `admin` изменён; созданы операторы с минимальными ролями
- [ ] `WAF_TRUSTED_PROXIES` сужен до подсети LB
- [ ] `WAF_FAIL_MODE=closed` (если политика «fail closed»)
- [ ] TLS: валидные сертификаты на сайтах или терминация на LB
- [ ] Секреты ИИ и ThreatFox не в git; только в `.env` или секрет-хранилище
- [ ] Резервное копирование тома `postgres_data`
- [ ] Мониторинг `/metrics` и диска ClamAV (`clamav_defs`)
- [ ] UI за корпоративным VPN / SSO; демо-логин отключён при необходимости

---

## 17. Устранение неполадок

| Симптом | Действие |
|---------|----------|
| `relation "sites" does not exist` | Перезапустить policy-api (миграции) или выполнить `db/003_sites_backends.sql` |
| В логах клиент = IP балансировщика | Настроить `WAF_TRUSTED_PROXIES` и заголовки на Nginx |
| ICAP «недоступен» | Дождаться загрузки сигнатур; проверить `clamav-icap:1344` из сети gateway |
| ИИ «не настроен» | `FENCE_AI_API_KEY` или ключ в UI → ИИ |
| 401 на API | Войти через `/auth/login`, передать Bearer token |
| Страна пустая на дашборде | Загрузить GeoLite2 Country в том geoip |
| После `git pull` ошибки колонок | Пересобрать и перезапустить policy-api |
| `go mod download` / `proxy.golang.org: i/o timeout` | В `deploy/.env` задать `GOPROXY=https://goproxy.io,direct` (или другое зеркало), затем `docker compose … build` |

Логи контейнеров:

```bash
docker compose -f deploy/docker-compose.yml logs -f policy-api waf-gateway
```

---

## 18. Обновление версии

```bash
git pull
docker compose -f deploy/docker-compose.yml build policy-api waf-gateway ui
docker compose -f deploy/docker-compose.yml up -d policy-api waf-gateway ui
```

При появлении новых файлов `db/NNN_*.sql` достаточно перезапуска policy-api — миграции применятся автоматически.
