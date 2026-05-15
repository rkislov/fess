# WAF Architecture Blueprint

## 1. Services

### waf-gateway (Go)
- Terminates HTTPS (or accepts decrypted traffic behind TLS terminator).
- Runs as reverse proxy.
- Supports HTTP/1.1, HTTP/2, and WebSocket handshake filtering.
- Evaluates request against active rule snapshot.

### policy-api (Go)
- CRUD for policies/rules/IP lists.
- Policy publish endpoint creates immutable version.
- Writes audit trail for all config changes.
- Emits policy update event to Redis.

### UI (React)
- Dashboard metrics and attack visibility.
- Rule editor + syntax highlight.
- Live logs via WebSocket.
- Replay tester for saved traffic samples.

## 2. On-the-fly Policy Apply

- Every gateway keeps active config in memory:
  - `atomic.Value` for lock-free reads on hot path.
  - write path compiles policy and swaps pointer atomically.
- Existing request continues with snapshot captured at request start.
- New requests observe latest policy immediately.

## 3. Rule Execution Model

Order:
1. Select enabled policies by priority.
2. For each policy, evaluate enabled rules by priority.
3. First terminal action wins:
   - `allow`, `block`, `redirect`, `replace`
4. `log` action is non-terminal unless configured as terminal.

Conditions:
- method
- path exact / **`path_prefix`** (starts with) / contains / regex
- **`client_ip_in`**, **`client_ip_not_in`** (CIDR/IP lists evaluated against effective client IP; see engine)
- headers
- query params
- body selectors (json/xml/form-urlencoded)
- ip/cidr
- env variables (`{REMOTE_ADDR}`, `{REQUEST_URI}`)

## 4. Data Plane and Control Plane Split

- Data plane: `waf-gateway` (fast path).
- Control plane: `policy-api` + PostgreSQL + Redis.
- Optional: central distributor for multi-region fanout.

## 5. Reliability Modes

- `fail-open`: pass traffic if policy engine unavailable.
- `fail-close`: block traffic if policy engine unavailable.

Mode must be explicit and configurable.

## 6. Performance Targets

- Rule evaluation budget: <= 1 ms average per rule match chain.
- Total extra latency at 50 rules: <= 5 ms average.

Optimization baseline:
- Precompile regex and expressions at publish time.
- Keep per-method and path-prefix indexes.
- Parse body only when body-dependent rules exist.

## 7. Observability

- Prometheus metrics:
  - `waf_requests_total`
  - `waf_blocked_total`
  - `waf_rule_eval_duration_seconds`
  - `waf_policy_version`
- Security logs to Loki/ELK.
- Audit log in PostgreSQL.

## 8. Delivery Roadmap

1. Proxy core + allow/block.
2. Dynamic policy updates.
3. Rule CRUD + logs UI.
4. Built-in attack signatures.
5. Learning mode and replay test.
6. Perf and resilience hardening.

## 9. Step-by-step Build Plan

### Step 1 (implemented)
- Basic reverse proxy and API service skeleton.
- PostgreSQL schema and local docker stack.

### Step 2 (implemented)
- Policy and rule CRUD in `policy-api`.
- Publish endpoint with Redis fanout event.
- Gateway policy reload from PostgreSQL and atomic snapshot swap.

### Step 3 (next)
- Add RBAC authentication for API/UI.
- Add UI app with policy/rule CRUD and live logs.

### Step 4 (partially done)
- Embedded OWASP CRS–inspired pack `crs-lite-v1` (`pkg/owasp/data/crs_lite_v1.json`): SQLi, XSS, traversal/LFI, RCE-style patterns, scanner UA.
- API: `GET /api/v1/owasp/packs`, `POST /api/v1/owasp/import` (optional `publish: true`).
- This is **not** a SecRules/CRS engine: conditions map to Fence’s JSON schema (`body_contains`, `request_uri_contains`, `path_regex`, etc.). Full CRS parity would need a SecRule parser or WASM ModSecurity.

### Step 4b (next)
- Optional external pack files (volume-mounted JSON) and versioning.
- Stricter parity: body/ARGS regex sets closer to CRS paranoia levels.
- Add learning mode controls and replay test endpoint.

### Step 5 (next)
- Prometheus metrics and Grafana dashboards.
- Benchmark suite for 5k RPS target and tuning.

### Step 6 (next)
- Kubernetes manifests/Helm.
- Cluster-wide policy convergence checks and audit export.
