# FESS — Frontend Security Server

WAF и reverse proxy с живым обновлением политик, антивирусом, IOC и веб-панелью.

**Автор:** Роман Сергеевич Кислов (Roman Sergeyevich Kislov)  
**Лицензия:** [Apache License 2.0](LICENSE)

Production-oriented blueprint for a dynamic Web Application Firewall (WAF) with on-the-fly policy updates, no service restart, and a web UI.

## Monorepo Layout

- `services/waf-gateway` - reverse proxy and enforcement engine
- `services/policy-api` - management API for policies/rules/logs/sites
- `pkg/engine` - rule matching/evaluation primitives
- `pkg/owasp` - embedded OWASP CRS–style rule packs (`data/crs_bundle_v1.json`, `crs_lite_v1.json`)
- `pkg/policy` - active policy snapshot store (atomic swap)
- `pkg/routing` - virtual host → upstream resolution for the gateway
- `pkg/tlssites` - TLS keypairs per site (SNI) for HTTPS on the gateway
- `db/schema.sql` - PostgreSQL schema
- `db/003_sites_backends.sql` - sites + backends tables and seed
- `db/007_site_tls.sql` - optional TLS PEM columns on `sites`
- `db/005_proxy_access_logs.sql` - журнал запросов через шлюз (host → upstream); миграции `006`…`011` дополняют поля (протокол, страна, **user_agent** и т.д.)
- `docs/openapi.yaml` - REST API contract
- `docs/blueprint.md` - architecture and rollout plan
- `docs/admin-guide.md` - **руководство администратора** (развёртывание, UI, `.env`)
- `deploy/.env.example` - шаблон переменных окружения для всего стека
- `deploy/docker-compose.yml` - local stack for development

## Core Runtime Pattern

1. Admin updates policy via `policy-api`.
2. `policy-api` validates, versions, stores in PostgreSQL.
3. Update event is published to Redis channel.
4. `waf-gateway` instances reload and atomically swap active policy snapshot.
5. New requests use new policy immediately.

**Sites / backends:** same pattern via Redis channel `routing_updated` and in-memory routing table in `waf-gateway` (no restart). TLS material for HTTPS is reloaded on the same channel.

## HTTPS and edge ports

- HTTP listener: `WAF_LISTEN_ADDR` (default `:8080`). Optional TLS listener: `WAF_TLS_LISTEN_ADDR` (empty = disabled; in `deploy/docker-compose.yml` example it is `:8443`).
- Typical host mapping for “standard” external ports: `- "80:8080"` and `- "443:8443"` on `waf-gateway` (the container process listens on high ports; binding 80/443 on the host is fine).
- Per-site PEM (full chain + private key) is configured in the UI; the gateway picks a certificate by SNI using the same host patterns as routing.
- If the DB volume was created before TLS support, restart **policy-api** so embedded SQL migrations apply (`db/007_site_tls.sql`), or run that file once manually if you use an old API binary without the migration embedded.

## Quick Start (Docker)

```bash
cp deploy/.env.example deploy/.env
# Отредактируйте deploy/.env (пароли, FENCE_JWT_SECRET, при необходимости ИИ)

docker compose -f deploy/docker-compose.yml up -d --build
```

Полное описание параметров и эксплуатации: **[docs/admin-guide.md](docs/admin-guide.md)**.

### Database migrations (automatic)

After Postgres is reachable, **policy-api** applies SQL from `db/NNN_*.sql` (e.g. `002_…`, `009_…`) in numeric order. Files are **embedded in the policy-api binary** (`fence/db`); applied versions are recorded in **`fence_schema_migrations`**. Each file runs in a transaction; a session **advisory lock** avoids races if several API instances start together.

- **New migration:** add `db/010_whatever.sql` (three-digit prefix + underscore + name) and **rebuild/redeploy policy-api** so the SQL is included in the image.
- **Emergency skip:** set **`FENCE_SKIP_DB_MIGRATE=1`** (API starts without applying migrations; use only if you must bring the process up while fixing SQL).

Compose still mounts `db/schema.sql` and numbered files into Postgres **initdb** for brand-new volumes; that is **idempotent** with automigrate (migrations typically use `IF NOT EXISTS` / `ON CONFLICT DO NOTHING`). You may later simplify initdb to `schema.sql` only and rely on policy-api for the rest.

**`relation "sites" does not exist`:** usually means the data volume predates `sites` and nothing applied `003`. Start a current **policy-api** build so migrations run; if the volume is from an ancient checkout without `fence_schema_migrations`, the same applies. As a last resort, run `db/003_sites_backends.sql` once:

```bash
docker compose -f deploy/docker-compose.yml exec -T postgres \
  psql -U fence -d fence < db/003_sites_backends.sql
```

Or with a local client: `psql "postgres://fence:fence@localhost:5432/fence?sslmode=disable" -f db/003_sites_backends.sql`.

**Persistence:** `deploy/docker-compose.yml` mounts **named volumes** `postgres_data` (PostgreSQL cluster) and `redis_data` (Redis AOF under `/data`). Обычный перезапуск контейнеров (`docker compose restart` или `down` без `-v`) **не удаляет** эти данные. Чтобы полностью стереть БД и Redis и заново прогнать init-скрипты Postgres: `docker compose -f deploy/docker-compose.yml down -v`, затем `up -d` (флаг `-v` удаляет именованные тома проекта).

Optional demo seed:

```bash
psql "postgres://fence:fence@localhost:5432/fence?sslmode=disable" -f db/seeds.sql
```

## API Smoke Flow

Create policy:

```bash
curl -sS -X POST http://localhost:8082/api/v1/policies \
  -H 'content-type: application/json' \
  -d '{"name":"api-policy","mode":"block","priority":10}'
```

Create rule in policy:

```bash
curl -sS -X POST http://localhost:8082/api/v1/policies/<policy-id>/rules \
  -H 'content-type: application/json' \
  -d '{"name":"block-bot-ua","action":"block","priority":10,"condition_json":{"header_contains":{"User-Agent":"bot"}}}'
```

Publish policy:

```bash
curl -sS -X POST http://localhost:8082/api/v1/policies/<policy-id>/publish
```

After publish, gateway applies it live without restart.

## OWASP CRS–inspired rule packs

List embedded packs:

```bash
curl -sS http://localhost:8082/api/v1/owasp/packs
```

Import the **full** embedded pack `crs-bundle-v1` (~80 rules) or the short `crs-lite-v1` (15 rules) into a new policy and publish (so gateways reload immediately):

```bash
curl -sS -X POST http://localhost:8082/api/v1/owasp/import \
  -H 'content-type: application/json' \
  -d '{"pack_id":"crs-bundle-v1","policy_name":"OWASP CRS","mode":"log","publish":true}'
```

Download the raw JSON for a pack (all rules, no truncation):

```bash
curl -sS -o owasp-pack.json 'http://localhost:8082/api/v1/owasp/pack?pack_id=crs-bundle-v1'
```

This is **not** a full ModSecurity CRS port: rules are expressed in Fence’s `condition_json` schema (subset of CRS ideas). The canonical CRS lives at [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset). Дополнительно: `path_prefix` (совпадение по префиксу пути), `client_ip_in` / `client_ip_not_in` (массивы IP или CIDR: эффективный клиентский IP совпадает с тем же разрешением, что и в журналах за прокси; для `client_ip_not_in` правило **не срабатывает**, если клиент попадает в одну из перечисленных сетей).

## Malware scanning (ClamAV ICAP by default; optional HTTP scanner)

**Default in `deploy/docker-compose.yml`:** сервис **`clamav-icap`** (**`opencloudeu/clamav-icap`**) слушает **TCP 1344**, сервис ICAP **`avscan`**. В записи **`malware_settings`** по умолчанию **`icap.enabled`:** **`true`**, **`host`:** **`clamav-icap`**. **`waf-gateway`** отправляет REQMOD по RFC 3507 **до** опционального шага **`external_scanner`** (можно оставить **`url`** пустым).

**Внешний HTTP-сканер:** второй необязательный слой на **`external_scanner.url`** — multipart **`upload`** + **`meta`** с **`content_type`**; ответ **`{"clean":…,"reason":…}`**.

**ICAP:** можно указать **любой** ICAP-сервер (не только compose), доступный из **`waf-gateway`** — **`host`**, **`port`** (часто **1344**), **`service`** (**`avscan`** или **`srv_clamav`** для этого образа).

**ClamAV mirror / freshclam snippet**: **`clamav_mirror.database_mirror`** задаёт строку для сниппета freshclam на хостах с ClamAV.

Первый запуск **`clamav-icap`** может занять несколько минут (**загрузка сигнатур**). Пока демоны не готовы, REQMOD может отдавать ошибку при **`fail_open`** **`false`**; в дефолтном конфиге включён **`fail_open`** **`true`** (пропуск при сбое ICAP).

**Про HTTP /health у внешнего сканера:** **`policy-api`** `GET …/malware/status` дергает **`GET …/healthz`** только если **`external_scanner.url`** не пустой (`…/scan` → `…/healthz`).

- **Live reload**: saving settings publishes **`malware_settings_updated`** on Redis; **`waf-gateway`** reloads without restart.

API:

- `GET/PUT /api/v1/settings/malware`
- `GET /api/v1/settings/malware/freshclam-snippet`
- `GET /api/v1/settings/malware/status` — ICAP/clamd/external probe summary

### Docker compose notes

- **`Exception in thread ... compose ... KeyError: 'id'`** — bug in obsolete **`docker-compose` v1**. Prefer **`docker compose`** (Compose V2).
- **`Redis ... vm.overcommit_memory`** — host kernel tuning; often ignorable locally.
- **`CLAMAV_CLAMD_PORT`** in **`policy-api`**: **`0`** (по умолчанию в compose) отключает probe **`VERSION`** к clamd по TCP; ICAP на порту **1344** проверяется отдельно. Укажите **3310**, если clamd слушает TCP на том же хосте, что и ICAP, и вы хотите версию в UI.

Документация по телам REQMOD, **`MaxObjectSize`** в **`virus_scan.conf`** и зеркалам freshclam см. в материалах вокруг образа **`opencloudeu/clamav-icap`** при необходимости тонкой настройки.

### Sites & backends (reverse proxy)

- `GET/POST /api/v1/sites` — virtual hosts: `host_pattern` exact (`api.example.com`), wildcard (`*.example.com`), or catch-all `*`; lower `priority` is tried first. Optional **`policy_id`**: if set, the gateway evaluates **only that enabled policy** for traffic matching the site; empty / omitted = **all** enabled policies (legacy).
- `PUT/DELETE /api/v1/sites/{id}`
- `GET/POST /api/v1/sites/{id}/backends` — origin `base_url` (`http://` or `https://`); optional **`tls_skip_verify`** (boolean): for HTTPS upstream, gateway uses `InsecureSkipVerify` when true (lab/self-signed only).
- `PUT/DELETE /api/v1/backends/{id}`

**Gateway & policy logs (read via policy-api)**

- `GET /api/v1/malware-scan-logs` — журнал проверок тел запросов антивирусом (чистые и с угрозой; query **`clean`** = `0`/`1`, пагинация). Пишет **waf-gateway** при каждом сканировании по правилам ICAP/сканеров (`db/013_malware_scan_logs.sql`).
- `GET /api/v1/proxy-access-logs` — журнал соединений (host, **client_ip** после LB при настройке **`WAF_TRUSTED_PROXIES`**, **tcp_peer** — прямой TCP к шлюзу, **backend_name** — имя выбранного бэкенда с минимальным приоритетом, **user_agent**, upstream URL, исход); пишет **waf-gateway** в `proxy_access_logs` (см. `db/005` … `db/011`). Пагинация: query **`limit`** (по умолчанию 100, максимум 200), **`offset`**; в JSON есть **`total`**, **`limit`**, **`offset`**.
- `GET /api/v1/logs` — журнал срабатываний правил и malware в `waf_logs` (policy_id, rule_id, details, …). Те же query **`limit`** / **`offset`** и поля **`total`** в ответе.
- **ИИ-помощник (вкладка «ИИ» в UI):** `GET /api/v1/settings/ai` — не раскрывает секреты: только признак наличия ключа, имя модели и базовый URL API. **`POST /api/v1/ai/analyze`** — собирает срез последних строк из `proxy_access_logs` и/или `waf_logs` и снимок политик/правил, отправляет во внешнюю модель (**OpenAI-совместимый** `/v1/chat/completions`). Обязательно задать **`FENCE_AI_API_KEY`** для процесса **`policy-api`**; необязательно **`FENCE_AI_BASE_URL`** (по умолчанию OpenAI), **`FENCE_AI_MODEL`** (по умолчанию **`gpt-4o-mini`**). Ответ модели не применяет правила автоматически — только рекомендации.
- **Срабатывания WAF (дашборд и деталка):** `GET /api/v1/waf-rule-hits` — агрегат по `rule_id`+`action` (query **`hours`**, пагинация). `GET /api/v1/waf-log-events` — список событий (фильтры **`rule_id`**, **`action`**). `GET /api/v1/waf-log-events/{id}` — детали (хост, сайты, правило, кэш **`ai_analysis`**). `POST /api/v1/waf-log-events/{id}/ai-review` — анализ одного события ИИ. `POST /api/v1/rules/{id}/quick-action` — тело `{"action":"enable"|"disable"|"log_only"|"block"}` + автоматическая публикация политики. В UI: топ‑10 на дашборде, кнопка «Далее» → полноэкранный журнал (`#waf-events`), клик по строке → карточка (`#waf-event/{id}`). Миграция **`db/012_waf_logs_host_ai.sql`** добавляет **`host`** и **`ai_analysis`** в `waf_logs` (шлюз пишет `host` для новых записей).

Live reload: Redis `routing_updated`. If nothing matches `Host`, gateway uses **`UPSTREAM_URL`**.

If the UI or API reports missing columns after `git pull`, **restart policy-api** (or redeploy the image) so automigrations run. Manual `psql` is only needed if you temporarily run an **old policy-api binary** that does not yet embed the new `db/NNN_*.sql` file.

## Multi-platform Docker (arm64 / amd64)

- **Go services** (`policy-api`, `waf-gateway`): Dockerfiles use BuildKit’s `TARGETARCH` (with a `uname -m` fallback) so the binary matches the image architecture (native **arm64** on Apple Silicon, **amd64** on typical servers).
- **Demo upstream**: `mccutchen/go-httpbin` is multi-arch (replaces `kennethreitz/httpbin`).
- **Base images** (`postgres`, `redis`, `golang`, `alpine`, `node`, `nginx`) are official multi-arch manifests.
- **`opencloudeu/clamav-icap`**: проверьте готовность архитектуры в [Docker Hub](https://hub.docker.com/r/opencloudeu/clamav-icap) (часто есть **amd64** и **arm64**).

To build and push a multi-arch manifest for Fence images (optional):

```bash
cd /path/to/fence
docker buildx create --use 2>/dev/null || true
docker buildx build --platform linux/amd64,linux/arm64 -f services/policy-api/Dockerfile -t yourrepo/fence-policy-api:tag --push .
```

## Service Endpoints

- UI (Nginx + static Nuxt build): `http://localhost:5173`
- WAF Gateway: `http://localhost:8080`
- Policy API (direct): `http://localhost:8082`
- **Real client IP behind a load balancer:** on `waf-gateway`, set **`WAF_TRUSTED_PROXIES`** to comma-separated **CIDRs of the immediate TCP hop(s) to this gateway** (who you see as **TCP peer** in proxy access logs when this is unset). Only then are `X-Forwarded-For` (first non-trusted IP left-to-right), `X-Real-IP`, `True-Client-IP`, and `CF-Connecting-IP` used for **`proxy_access_logs.client_ip`**, **`waf_logs.source_ip`**, GeoIP, and structured access logs. If the TCP peer is **not** in that list, inbound forwarded headers are ignored for resolving the client (spoofing-safe). **Toward backends**, the gateway always sets **`X-Real-IP`** to that effective client; **`X-Forwarded-For`** is filled when empty, **replaced entirely** when `WAF_TRUSTED_PROXIES` is unset (so clients cannot inject a fake chain through Fence), and **left unchanged** when it was already set by a trusted hop. **`X-Forwarded-Proto`** is added when missing.
- **Dashboard map / `country_code` in access logs:** set **`GEOIP_MMDB_PATH`** on `waf-gateway` to a MaxMind **GeoLite2 Country** `.mmdb` file (or rely on **`CF-IPCountry`** from Cloudflare). In **`deploy/docker-compose.yml`** a named volume **`fence_geoip_data`** is mounted at **`/var/lib/fence/geoip`** on **`policy-api`** (read-write) and **`waf-gateway`** (read-only) with **`GEOIP_MMDB_PATH=/var/lib/fence/geoip/GeoLite2-Country.mmdb`**. Install the file from the UI (**Malware → GeoIP**: upload or HTTPS fetch) or copy it into the volume manually, then the gateway reloads the reader via Redis (`geoip_mmdb_updated`) without a container restart. If the file is missing, the gateway logs a GeoIP open error and country stays empty until fixed.

### Nginx перед `waf-gateway` (частая путаница)

В Nginx директивы **`set_real_ip_from`** / **`real_ip_header`** / **`real_ip_recursive`** меняют только **`$remote_addr` внутри Nginx** (чтобы Nginx «видел» клиента за своим верхним LB). **Fence этого не знает:** он не читает конфиг Nginx и по умолчанию считает клиентом **тот IP, с которого пришёл TCP к `waf-gateway`** (часто IP контейнера/хоста Nginx).

Чтобы в логах Fence был реальный клиент:

1. На **`waf-gateway`** задайте **`WAF_TRUSTED_PROXIES`** — CIDR **источника TCP к шлюзу** (обычно подсеть или IP **Nginx**, как он виден из контейнера `waf-gateway`). Это может отличаться от `set_real_ip_from` в Nginx: там перечисляют «кто перед Nginx», а для Fence нужен «кто непосредственно подключается к `waf-gateway`». Подсказка: временно оставьте `WAF_TRUSTED_PROXIES` пустым, сделайте запрос и посмотрите **«TCP пир»** в UI — в trusted нужно включить именно этот адрес (или его подсеть).
2. В **`location`**, который проксирует на Fence, передавайте цепочку клиента, например:
   ```nginx
   proxy_set_header Host              $host;
   proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
   # при необходимости: proxy_set_header X-Real-IP $remote_addr;
   ```
   После `real_ip` в Nginx **`$remote_addr`** уже «настоящий» клиент, поэтому **`$proxy_add_x_forwarded_for`** допишет корректный хвост в `X-Forwarded-For` для Fence.

Если Nginx и `waf-gateway` в одной Docker-сети, TCP-пир часто **`172.x.x.x`** — тогда в **`WAF_TRUSTED_PROXIES`** нужна эта подсеть (например `172.18.0.0/16`), а не только `10.20.30.0/28`.

3. К **origin** (Nextcloud и т.д.) шлюз сам дописывает **`X-Real-IP`** и при необходимости **`X-Forwarded-For`** / **`X-Forwarded-Proto`** — см. описание в пункте про `WAF_TRUSTED_PROXIES` выше.

- Demo upstream (`go-httpbin`, multi-arch / **arm64** friendly): `http://localhost:8081` → WAF uses `http://httpbin:8080` inside the stack.

UI uses Nginx proxy and forwards `/api/*` to `policy-api`.

**Конфигурация:** все переменные окружения для compose — в **`deploy/.env`** (шаблон **`deploy/.env.example`**). Секреты не коммитьте; файл `deploy/.env` в `.gitignore`.

**UI sign-in (demo):** the static Nuxt app shows a login screen that only protects the browser session (credentials are checked in the client bundle). Defaults: `FENCE_UI_USER` / `FENCE_UI_PASSWORD` in `.env` (default `admin` / `fence`). **API auth:** JWT via `POST /api/v1/auth/login` — см. admin guide (`FENCE_JWT_SECRET`, пользователи в UI). Set `FENCE_UI_AUTH_ENABLED=false` to hide the demo login behind SSO.

## Next Engineering Steps

1. Implement OpenAPI endpoints and request validation.
2. Add policy compiler (regex/expr precompilation).
3. Implement request pipeline (match -> action -> log).
4. Integrate Redis pub/sub for live updates.
5. Add auth + RBAC for UI/API.
