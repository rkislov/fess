-- Per-backend path routing and WebSocket upgrade passthrough (no body buffer / ICAP on handshake).
ALTER TABLE backends
  ADD COLUMN IF NOT EXISTS path_prefix TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS websocket_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN backends.path_prefix IS 'Optional URI prefix for this backend on the site host (e.g. /ws). Longest match wins; empty = site default.';
COMMENT ON COLUMN backends.websocket_enabled IS 'When true, WebSocket upgrade requests matching this backend are proxied without buffering the body.';
